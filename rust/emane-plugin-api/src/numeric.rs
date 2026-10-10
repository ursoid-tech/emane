//! Native conversions for the numeric syntax accepted by C++ ParameterConvert.
//! Integer scaling operates on text, retaining precision above 2^53.
pub trait LegacyNumber: Sized {
    fn from_normalized(value: &str) -> Option<Self>;
}
pub trait LegacyParse {
    fn parse_legacy<T: LegacyNumber>(&self) -> Result<T, String>;
}
impl LegacyParse for str {
    fn parse_legacy<T: LegacyNumber>(&self) -> Result<T, String> {
        normalize_numeric(self)
            .and_then(|s| T::from_normalized(&s))
            .ok_or_else(|| format!("invalid numeric value: {self}"))
    }
}
fn magnitude(value: &str) -> Option<(bool, u64)> {
    let negative = value.starts_with('-');
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    let (radix, digits) = if let Some(digits) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, digits)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    Some((negative, u64::from_str_radix(digits, radix).ok()?))
}
macro_rules! integer {
    ($($t:ty),*) => { $(impl LegacyNumber for $t {
        fn from_normalized(value: &str) -> Option<Self> {
            let (negative, magnitude) = magnitude(value)?;
            let value = if <$t>::MIN == 0 {
                (if negative { magnitude.wrapping_neg() } else { magnitude }) as i128
            } else if negative { -(magnitude as i128) } else { magnitude as i128 };
            Self::try_from(value).ok()
        }
    })* };
}
integer!(u8, u16, u32, u64, i8, i16, i32, i64);
impl LegacyNumber for f64 {
    fn from_normalized(value: &str) -> Option<Self> {
        parse_float(value)
    }
}
impl LegacyNumber for f32 {
    fn from_normalized(value: &str) -> Option<Self> {
        let value = f64::from_normalized(value)?;
        (value.is_nan() || value.abs() <= f32::MAX as f64).then_some(value as f32)
    }
}
// C strtod accepts hexadecimal significands and NaN payloads. Keep this
// conversion native while retaining its range-error and lexical behavior.
fn parse_float(value: &str) -> Option<f64> {
    let negative = value.starts_with('-');
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let lower = unsigned.to_ascii_lowercase();
    if lower == "nan"
        || lower
            .strip_prefix("nan(")
            .and_then(|s| s.strip_suffix(')'))
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Some(if negative { -f64::NAN } else { f64::NAN });
    }
    if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        return parse_hex_float(hex, negative);
    }
    let number = value.parse::<f64>().ok()?;
    let nonzero = unsigned
        .split(['e', 'E'])
        .next()?
        .bytes()
        .any(|b| matches!(b, b'1'..=b'9'));
    // Decimal conversion reports ERANGE for subnormal and underflowed values.
    if !number.is_finite() || number.is_subnormal() || (number == 0.0 && nonzero) {
        return None;
    }
    Some(number)
}

fn parse_hex_float(value: &str, negative: bool) -> Option<f64> {
    let (significand, exponent) = value.split_once(['p', 'P']).unwrap_or((value, "0"));
    let exp_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let exponent = exp_digits.bytes().fold(0i64, |n, b| {
        n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
    });
    let exponent = if value
        .split_once(['p', 'P'])
        .is_some_and(|(_, e)| e.starts_with('-'))
    {
        -exponent
    } else {
        exponent
    };
    let mut bits = Vec::new();
    let mut fraction_digits = 0i64;
    let mut dot = false;
    let mut digits = 0;
    for c in significand.chars() {
        if c == '.' {
            if dot {
                return None;
            }
            dot = true;
        } else {
            let digit = c.to_digit(16)?;
            digits += 1;
            fraction_digits += i64::from(dot);
            for shift in (0..4).rev() {
                bits.push((digit >> shift & 1) as u8);
            }
        }
    }
    if digits == 0 {
        return None;
    }
    let sign = u64::from(negative) << 63;
    let Some(first) = bits.iter().position(|b| *b != 0) else {
        return Some(f64::from_bits(sign));
    };
    let bits = &bits[first..];
    let mut top = exponent
        .saturating_sub(fraction_digits.saturating_mul(4))
        .saturating_add(bits.len() as i64 - 1);
    if !(-1074..=1023).contains(&top) {
        return None;
    }
    let keep = if top >= -1022 {
        53
    } else {
        (top + 1075) as usize
    };
    let mut mantissa = 0u64;
    for i in 0..keep {
        mantissa = (mantissa << 1) | u64::from(bits.get(i).copied().unwrap_or(0));
    }
    let discarded = bits.get(keep..).unwrap_or_default();
    if top < -1022 {
        // Exact hexadecimal subnormals are accepted by strtod; rounded ones
        // signal ERANGE even when their rounded result is nonzero.
        if discarded.contains(&1) {
            return None;
        }
        return Some(f64::from_bits(sign | mantissa));
    }
    if discarded.first() == Some(&1) && (mantissa & 1 != 0 || discarded[1..].contains(&1)) {
        mantissa += 1;
        if mantissa == 1 << 53 {
            mantissa >>= 1;
            top += 1;
        }
    }
    if top > 1023 {
        return None;
    }
    Some(f64::from_bits(
        sign | (((top + 1023) as u64) << 52) | (mantissa & ((1 << 52) - 1)),
    ))
}

// C++ ParameterConvert scales the decimal text before integer/float conversion.
// Keep integer values exact beyond 2^53 and preserve base-0 integer parsing.
fn normalize_numeric(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let power = match value.as_bytes().last()? {
        b'K' => 3,
        b'M' => 6,
        b'G' => 9,
        _ => 0,
    };
    if power == 0 {
        return Some(
            value
                .trim_start_matches(|c: char| c.is_ascii_whitespace())
                .to_string(),
        );
    }
    let mut number = value[..value.len() - 1]
        .trim_start_matches(|c: char| c.is_ascii_whitespace())
        .to_string();
    if let Some(dot) = number.find('.') {
        let fraction = number.len() - dot - 1;
        if fraction > power {
            number.insert(dot + power, '.');
        } else {
            number.extend(std::iter::repeat_n('0', power - fraction));
        }
        number.remove(dot);
    } else {
        number.extend(std::iter::repeat_n('0', power));
    }
    let sign = if number.starts_with(['+', '-']) {
        &number[..1]
    } else {
        ""
    };
    let digits = number[sign.len()..].trim_start_matches('0');
    Some(format!(
        "{sign}{}",
        if digits.is_empty() { "0" } else { digits }
    ))
}

#[cfg(test)]
mod tests {
    use super::LegacyParse;
    #[test]
    fn c_float_lexical_range_and_hex_rounding() {
        for (text, bits) in [
            ("0x1p2", 4.0f64.to_bits()),
            ("0x1.8p2", 6.0f64.to_bits()),
            ("-0x0p999999", (-0.0f64).to_bits()),
            ("0x1p-1074", 1),
            ("0x1.fffffffffffffp1023", f64::MAX.to_bits()),
            ("0x1.00000000000008p0", 1.0f64.to_bits()),
            ("0x1.00000000000018p0", 1.0f64.to_bits() + 2),
        ] {
            assert_eq!(
                text.parse_legacy::<f64>().unwrap().to_bits(),
                bits,
                "{text}"
            );
        }
        assert!("nan(payload_1)".parse_legacy::<f64>().unwrap().is_nan());
        assert_eq!("0e-999999".parse_legacy::<f64>().unwrap(), 0.0);
        for text in [
            "1e-320",
            "1e-400",
            "0x1.1p-1074",
            "0x1p1024",
            "0x1p-1075",
            "nan(bad!)",
            "0x1p",
            "\u{a0}1",
        ] {
            assert!(text.parse_legacy::<f64>().is_err(), "{text}");
        }
    }
    #[test]
    fn cpp_numbers_preserve_integer_precision_and_lexical_rules() {
        assert_eq!("0x20".parse_legacy::<u16>().unwrap(), 32);
        assert_eq!("010".parse_legacy::<u16>().unwrap(), 8);
        assert_eq!("1.5M".parse_legacy::<u64>().unwrap(), 1_500_000);
        assert_eq!(
            "9007199254740993K".parse_legacy::<u64>().unwrap(),
            9007199254740993000
        );
        assert_eq!(" -1".parse_legacy::<i32>().unwrap(), -1);
        assert_eq!("-1".parse_legacy::<u64>().unwrap(), u64::MAX);
        assert_eq!("1e2".parse_legacy::<f32>().unwrap(), 100.0);
        assert!("NaN".parse_legacy::<f32>().unwrap().is_nan());
        for value in ["1.5", "1m", "1 ", "65536", "-1"] {
            assert!(value.parse_legacy::<u16>().is_err(), "{value}");
        }
    }
}
