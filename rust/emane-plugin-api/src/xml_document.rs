//! Native validation of EMANE's DTD vocabulary. No native XML dependency.
//! Supports external file subsets/parameter entities, general entities, default
//! and fixed attributes, enumerations, and regular element content models.
//! Unsupported DTD constructs fail explicitly instead of bypassing validation.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn tokens(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let mut token = String::from(c);
        if c == '\'' || c == '"' {
            loop {
                let next = chars.next().ok_or("unterminated DTD literal")?;
                token.push(next);
                if next == c {
                    break;
                }
            }
        } else if !"(),|?*+%".contains(c) {
            while chars
                .peek()
                .is_some_and(|c| !c.is_whitespace() && !"(),|?*+%".contains(*c))
            {
                token.push(chars.next().unwrap());
            }
        }
        out.push(token);
    }
    Ok(out)
}
fn literal(s: &str) -> Result<&str, String> {
    if s.len() >= 2 && (s.starts_with('"') || s.starts_with('\'')) {
        Ok(&s[1..s.len() - 1])
    } else {
        Err(format!("expected DTD literal, got {s}"))
    }
}
fn declaration_end(s: &str) -> Result<usize, String> {
    let mut quote = None;
    let mut subset = 0;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else {
            match c {
                '\'' | '"' => quote = Some(c),
                '[' => subset += 1,
                ']' => subset -= 1,
                '>' if subset == 0 => return Ok(i + 1),
                _ => {}
            }
        }
    }
    Err("unterminated XML declaration".into())
}
fn resolve(base: &Path, uri: &str) -> Result<PathBuf, String> {
    let uri = uri.strip_prefix("file://").unwrap_or(uri);
    if uri.contains("://") {
        return Err(format!(
            "unsupported external XML URI: {uri}; use a local file"
        ));
    }
    Ok(base.parent().unwrap_or(Path::new(".")).join(uri))
}
#[derive(Default)]
struct Subset {
    parameters: BTreeMap<String, String>,
    expansions: usize,
}
impl Subset {
    fn expand(&mut self, text: &str, base: &Path, depth: usize) -> Result<String, String> {
        if depth > 32 {
            return Err("DTD entity nesting limit exceeded".into());
        }
        let mut rest = text;
        let mut out = String::new();
        while !rest.is_empty() {
            if rest.starts_with("<!--") {
                let end = rest.find("-->").ok_or("unterminated DTD comment")? + 3;
                rest = &rest[end..];
                continue;
            }
            if rest.starts_with("<?") {
                let end = rest.find("?>").ok_or("unterminated DTD instruction")? + 2;
                rest = &rest[end..];
                continue;
            }
            if rest.starts_with("<!ENTITY") {
                let end = declaration_end(rest)?;
                let t = tokens(&rest[8..end - 1])?;
                let parameter = t.first().is_some_and(|t| t == "%");
                let t = if parameter { &t[1..] } else { &t[..] };
                if t.len() < 2 {
                    return Err("invalid DTD entity".into());
                }
                let value = if matches!(t[1].as_str(), "SYSTEM" | "PUBLIC") {
                    let uri = t
                        .get(if t[1] == "SYSTEM" { 2 } else { 3 })
                        .ok_or("missing entity URI")?;
                    let path = resolve(base, literal(uri)?)?;
                    let input = std::fs::read_to_string(&path)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    if parameter {
                        self.expand(&input, &path, depth + 1)?
                    } else {
                        input
                    }
                } else {
                    literal(&t[1])?.to_string()
                };
                if parameter {
                    self.parameters.entry(t[0].clone()).or_insert(value);
                } else {
                    out.push_str(&format!(
                        "<!ENTITY {} \"{}\">",
                        t[0],
                        value.replace('"', "&quot;")
                    ));
                }
                rest = &rest[end..];
                continue;
            }
            if rest.starts_with('%') {
                let end = rest.find(';').ok_or("unterminated parameter entity")?;
                let value = self
                    .parameters
                    .get(&rest[1..end])
                    .ok_or("unknown parameter entity")?
                    .clone();
                self.expansions += 1;
                if self.expansions > 10000 {
                    return Err("DTD expansion limit exceeded".into());
                }
                out.push_str(&self.expand(&value, base, depth + 1)?);
                rest = &rest[end + 1..];
                continue;
            }
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
            if out.len() > 16 * 1024 * 1024 {
                return Err("DTD expansion size limit exceeded".into());
            }
        }
        Ok(out)
    }
}
#[derive(Clone)]
enum Model {
    Name(String),
    Sequence(Vec<Model>),
    Choice(Vec<Model>),
    Repeat(Box<Model>, usize, usize),
    Empty,
    Any,
    Text,
}
fn model(t: &[String], i: &mut usize) -> Result<Model, String> {
    let token = t.get(*i).ok_or("missing content model")?;
    *i += 1;
    let mut result = if token == "(" {
        let mut items = vec![model(t, i)?];
        let mut separator = None;
        while t.get(*i).is_some_and(|s| s != ")") {
            let sep = &t[*i];
            if !matches!(sep.as_str(), "," | "|") || separator.as_ref().is_some_and(|s| s != sep) {
                return Err("invalid content model separator".into());
            }
            separator = Some(sep.clone());
            *i += 1;
            items.push(model(t, i)?);
        }
        if t.get(*i).map(String::as_str) != Some(")") {
            return Err("unclosed content model".into());
        }
        *i += 1;
        if separator.as_deref() == Some("|") {
            Model::Choice(items)
        } else {
            Model::Sequence(items)
        }
    } else {
        match token.as_str() {
            "EMPTY" => Model::Empty,
            "ANY" => Model::Any,
            "#PCDATA" => Model::Text,
            _ => Model::Name(token.clone()),
        }
    };
    if let Some(op) = t.get(*i) {
        if matches!(op.as_str(), "?" | "*" | "+") {
            result = Model::Repeat(
                Box::new(result),
                usize::from(op == "+"),
                if op == "?" { 1 } else { usize::MAX },
            );
            *i += 1;
        }
    }
    Ok(result)
}
impl Model {
    fn positions(&self, children: &[&str], start: usize) -> BTreeSet<usize> {
        match self {
            Self::Empty | Self::Text => BTreeSet::from([start]),
            Self::Any => (start..=children.len()).collect(),
            Self::Name(name) => {
                if children.get(start) == Some(&name.as_str()) {
                    BTreeSet::from([start + 1])
                } else {
                    BTreeSet::new()
                }
            }
            Self::Choice(items) => items
                .iter()
                .flat_map(|m| m.positions(children, start))
                .collect(),
            Self::Sequence(items) => items.iter().fold(BTreeSet::from([start]), |set, m| {
                set.into_iter()
                    .flat_map(|p| m.positions(children, p))
                    .collect()
            }),
            Self::Repeat(m, min, max) => {
                let mut result = if *min == 0 {
                    BTreeSet::from([start])
                } else {
                    BTreeSet::new()
                };
                let mut frontier = BTreeSet::from([start]);
                for _ in 0..(*max).min(children.len() + 1) {
                    let next: BTreeSet<_> = frontier
                        .iter()
                        .flat_map(|p| m.positions(children, *p))
                        .collect();
                    result.extend(&next);
                    let unseen = next.difference(&frontier).copied().collect::<BTreeSet<_>>();
                    if unseen.is_empty() {
                        break;
                    }
                    frontier = unseen;
                }
                result
            }
        }
    }
    fn text(&self) -> bool {
        match self {
            Self::Text | Self::Any => true,
            Self::Choice(v) | Self::Sequence(v) => v.iter().any(Self::text),
            Self::Repeat(m, _, _) => m.text(),
            _ => false,
        }
    }
}
struct Attribute {
    kind: String,
    enumeration: Vec<String>,
    default: Option<String>,
    required: bool,
    fixed: bool,
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
        .replace('"', "&quot;")
}

/// Locate a prolog DOCTYPE without interpreting examples inside XML comments.
fn doctype_start(input: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(i) = input[offset..].find('<') {
        offset += i;
        let rest = &input[offset..];
        let skip = if rest.starts_with("<!--") {
            rest.find("-->")? + 3
        } else if rest.starts_with("<?") {
            rest.find("?>")? + 2
        } else {
            return rest.starts_with("<!DOCTYPE").then_some(offset);
        };
        offset += skip;
    }
    None
}
pub fn has_doctype(input: &str) -> bool {
    doctype_start(input).is_some()
}

pub fn read(path: impl AsRef<Path>) -> Result<String, String> {
    let path = path.as_ref();
    let input = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let Some(start) = doctype_start(&input) else {
        return Ok(input);
    };
    let end = start + declaration_end(&input[start..])?;
    let declaration = &input[start + 9..end - 1];
    let (header, internal) = if let Some(i) = declaration.find('[') {
        (
            declaration[..i].trim(),
            declaration[i + 1..]
                .trim_end()
                .strip_suffix(']')
                .ok_or("invalid internal subset")?,
        )
    } else {
        (declaration.trim(), "")
    };
    let header = tokens(header)?;
    let root_name = header.first().ok_or("missing DOCTYPE name")?;
    let mut subset = Subset::default();
    let mut dtd = subset.expand(internal, path, 0)?;
    if header.len() > 1 {
        let uri = header
            .get(if header[1] == "SYSTEM" {
                2
            } else if header[1] == "PUBLIC" {
                3
            } else {
                return Err("unsupported DOCTYPE".into());
            })
            .ok_or("missing DTD URI")?;
        let dtd_path = resolve(path, literal(uri)?)?;
        let external = std::fs::read_to_string(&dtd_path)
            .map_err(|e| format!("{}: {e}", dtd_path.display()))?;
        dtd.push_str(&subset.expand(&external, &dtd_path, 0)?);
    }
    let mut models = BTreeMap::new();
    let mut attrs: BTreeMap<String, BTreeMap<String, Attribute>> = BTreeMap::new();
    let mut rest = dtd.as_str();
    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        if !rest.starts_with("<!") {
            return Err("unsupported DTD construct".into());
        }
        let end = declaration_end(rest)?;
        let t = tokens(&rest[2..end - 1])?;
        match t.first().map(String::as_str) {
            Some("ELEMENT") => {
                let mut i = 2;
                let m = model(&t, &mut i)?;
                if i != t.len() {
                    return Err("trailing content model tokens".into());
                }
                models.insert(t[1].clone(), m);
            }
            Some("ATTLIST") => {
                let table = attrs
                    .entry(t.get(1).ok_or("missing ATTLIST name")?.clone())
                    .or_default();
                let mut i = 2;
                while i < t.len() {
                    let name = t[i].clone();
                    i += 1;
                    let kind = t.get(i).ok_or("missing attribute type")?.clone();
                    i += 1;
                    let mut enumeration = Vec::new();
                    if kind == "(" {
                        while t.get(i).is_some_and(|s| s != ")") {
                            if t[i] != "|" {
                                enumeration.push(t[i].clone());
                            }
                            i += 1;
                        }
                        i += 1;
                    } else if !matches!(
                        kind.as_str(),
                        "CDATA" | "NMTOKEN" | "NMTOKENS" | "ID" | "IDREF" | "IDREFS"
                    ) {
                        return Err(format!("unsupported DTD attribute type {kind}"));
                    }
                    let rule = t.get(i).ok_or("missing attribute rule")?;
                    i += 1;
                    let required = rule == "#REQUIRED";
                    let fixed = rule == "#FIXED";
                    let default = if fixed {
                        let v = literal(t.get(i).ok_or("missing fixed value")?)?.to_string();
                        i += 1;
                        Some(v)
                    } else if rule == "#IMPLIED" || required {
                        None
                    } else {
                        Some(literal(rule)?.to_string())
                    };
                    table.entry(name).or_insert(Attribute {
                        kind,
                        enumeration,
                        default,
                        required,
                        fixed,
                    });
                }
            }
            Some("ENTITY") => {}
            _ => return Err("unsupported DTD declaration".into()),
        }
        rest = &rest[end..];
    }
    // roxmltree expands entities in explicit attributes, but does not supply
    // DTD defaults. Normalize defaults through the same XML parser first.
    for table in attrs.values_mut() {
        for rule in table.values_mut() {
            if let Some(value) = &mut rule.default {
                let sample = format!(
                    "<!DOCTYPE default [{dtd}]><default value=\"{}\"/>",
                    value.replace('"', "&quot;")
                );
                let parsed = roxmltree::Document::parse_with_options(
                    &sample,
                    roxmltree::ParsingOptions {
                        allow_dtd: true,
                        ..Default::default()
                    },
                )
                .map_err(|e| e.to_string())?;
                *value = parsed.root_element().attribute("value").unwrap().to_owned();
                if rule.kind != "CDATA" {
                    *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
                }
            }
        }
    }
    let expanded = format!(
        "{}<!DOCTYPE {root_name} [{dtd}]>{}",
        &input[..start],
        &input[end..]
    );
    let doc = roxmltree::Document::parse_with_options(
        &expanded,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if doc.root_element().tag_name().name() != root_name {
        return Err("DOCTYPE root mismatch".into());
    }
    let mut output = format!("<!DOCTYPE {root_name} [{dtd}]>");
    let mut ids = BTreeSet::new();
    let mut references = Vec::new();
    fn emit(
        node: roxmltree::Node<'_, '_>,
        models: &BTreeMap<String, Model>,
        attrs: &BTreeMap<String, BTreeMap<String, Attribute>>,
        out: &mut String,
        ids: &mut BTreeSet<String>,
        refs: &mut Vec<String>,
    ) -> Result<(), String> {
        if node.is_text() {
            out.push_str(&escape(node.text().unwrap_or("")));
            return Ok(());
        }
        if !node.is_element() {
            return Ok(());
        }
        let name = node.tag_name().name();
        let model = models
            .get(name)
            .ok_or_else(|| format!("undeclared element {name}"))?;
        let children: Vec<_> = node
            .children()
            .filter(|n| n.is_element())
            .map(|n| n.tag_name().name())
            .collect();
        if (matches!(model, Model::Empty) && node.children().any(|n| n.is_text()))
            || !model.positions(&children, 0).contains(&children.len())
            || (!model.text()
                && node
                    .children()
                    .any(|n| n.is_text() && !n.text().unwrap_or("").trim().is_empty()))
        {
            return Err(format!("invalid contents of {name}"));
        }
        let empty = BTreeMap::new();
        let table = attrs.get(name).unwrap_or(&empty);
        let mut values: BTreeMap<String, String> = node
            .attributes()
            .map(|a| (a.name().to_string(), a.value().to_string()))
            .collect();
        if node.tag_name().namespace().is_some()
            || node.attributes().any(|a| a.namespace().is_some())
        {
            return Err("namespaced DTD documents are not supported".into());
        }
        for attr in values.keys() {
            if !table.contains_key(attr) {
                return Err(format!("undeclared attribute {attr} on {name}"));
            }
        }
        for (attr, rule) in table {
            if !values.contains_key(attr) {
                if let Some(default) = &rule.default {
                    values.insert(attr.clone(), default.clone());
                } else if rule.required {
                    return Err(format!("missing {attr} on {name}"));
                }
            }
            if let Some(value) = values.get_mut(attr) {
                if rule.kind != "CDATA" {
                    *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                if (rule.fixed && rule.default.as_ref() != Some(value))
                    || (!rule.enumeration.is_empty() && !rule.enumeration.contains(value))
                {
                    return Err(format!("invalid {attr} on {name}"));
                }
                if matches!(
                    rule.kind.as_str(),
                    "NMTOKEN" | "NMTOKENS" | "ID" | "IDREF" | "IDREFS"
                ) {
                    let words = value.split_whitespace().collect::<Vec<_>>();
                    if words.is_empty()
                        || (!rule.kind.ends_with('S') && words.len() != 1)
                        || words
                            .iter()
                            .any(|w| !w.chars().all(|c| c.is_alphanumeric() || "_.:-".contains(c)))
                    {
                        return Err(format!("invalid XML name token {value}"));
                    }
                    if rule.kind.starts_with("ID")
                        && words.iter().any(|w| {
                            !w.chars()
                                .next()
                                .is_some_and(|c| c.is_alphabetic() || "_:".contains(c))
                        })
                    {
                        return Err(format!("invalid XML ID token {value}"));
                    }
                    if rule.kind == "ID" && !ids.insert(value.clone()) {
                        return Err("duplicate XML ID".into());
                    }
                    if rule.kind.starts_with("IDREF") {
                        refs.extend(words.into_iter().map(str::to_owned));
                    }
                }
            }
        }
        out.push('<');
        out.push_str(name);
        for (key, value) in values {
            out.push_str(&format!(
                " {key}=\"{}\"",
                escape(&value).replace('\n', "&#10;").replace('\t', "&#9;")
            ));
        }
        out.push('>');
        for child in node.children() {
            emit(child, models, attrs, out, ids, refs)?;
        }
        out.push_str(&format!("</{name}>"));
        Ok(())
    }
    emit(
        doc.root_element(),
        &models,
        &attrs,
        &mut output,
        &mut ids,
        &mut references,
    )?;
    if references.iter().any(|r| !ids.contains(r)) {
        return Err("unresolved XML IDREF".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_parameter_entities_defaults_and_content_validation() {
        let dir = std::env::temp_dir().join(format!("emane-native-dtd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrs.ent"),
            "name CDATA '&value;' mode (one|two) #FIXED '  one  '",
        )
        .unwrap();
        std::fs::write(dir.join("test.dtd"),"<!ENTITY % attrs SYSTEM 'attrs.ent'><!ELEMENT root (item+)><!ATTLIST root %attrs;><!ELEMENT item EMPTY><!ATTLIST item value CDATA #REQUIRED>").unwrap();
        let path = dir.join("test.xml");
        std::fs::write(&path,"<!DOCTYPE root SYSTEM 'test.dtd' [<!ENTITY value 'expanded'>]><root><item value='&value;'/></root>").unwrap();
        let xml = read(&path).unwrap();
        let doc = roxmltree::Document::parse_with_options(
            &xml,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(doc.root_element().attribute("name"), Some("expanded"));
        assert_eq!(
            doc.root_element()
                .first_element_child()
                .unwrap()
                .attribute("value"),
            Some("expanded")
        );
        for invalid in [
            "<root/>",
            "<root mode='three'><item value='1'/></root>",
            "<root><item/></root>",
            "<root extra='1'><item value='1'/></root>",
        ] {
            std::fs::write(
                &path,
                format!("<!DOCTYPE root SYSTEM 'test.dtd' [<!ENTITY value 'expanded'>]>{invalid}"),
            )
            .unwrap();
            assert!(read(&path).is_err(), "{invalid}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
