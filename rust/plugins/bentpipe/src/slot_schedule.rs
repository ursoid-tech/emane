use super::Transponder;
use std::collections::BTreeSet;

// The original protocol builds opportunities in batches of 100 frames. The
// slot clock is fixed when the protocol is constructed; runtime configuration
// affects future batches and MTU calculation without resetting that clock.
pub(super) struct SlotSchedule {
    slot_size: u64,
    slots_per_frame: u16,
    last_scheduled_frame: u64,
    pending: BTreeSet<u64>,
}

impl SlotSchedule {
    pub(super) fn new(transponder: &Transponder, now: i64) -> Self {
        let slot_size = transponder
            .protocol_slot_size
            .unwrap_or(transponder.transmit_slot_size_us);
        let slot = now.max(0) as u64 / slot_size;
        let frame = slot / u64::from(transponder.transmit_slots_per_frame);
        let mut schedule = Self {
            slot_size,
            slots_per_frame: transponder.transmit_slots_per_frame,
            last_scheduled_frame: frame + 99,
            pending: BTreeSet::new(),
        };
        schedule.fill(transponder, slot);
        schedule
    }

    fn fill(&mut self, transponder: &Transponder, mut slot: u64) {
        let mut relative = slot % u64::from(self.slots_per_frame);
        for _ in 0..100 {
            while relative < u64::from(transponder.transmit_slots_per_frame) {
                if transponder
                    .transmit_slots
                    .binary_search(&(relative as u16))
                    .is_ok()
                {
                    self.pending.insert(slot);
                }
                slot += 1;
                relative += 1;
            }
            relative = 0;
        }
    }

    fn refill(&mut self, transponder: &Transponder, slot: u64, frame: u64) {
        if self.last_scheduled_frame == frame {
            self.fill(transponder, (frame + 1) * u64::from(self.slots_per_frame));
            self.last_scheduled_frame = frame + 100;
        } else {
            self.fill(transponder, slot);
            self.last_scheduled_frame = frame + 99;
        }
    }

    pub(super) fn next_time(&self) -> Option<i64> {
        self.pending
            .first()
            .map(|slot| (slot * self.slot_size) as i64)
    }

    pub(super) fn check(
        &mut self,
        transponder: &Transponder,
        now: i64,
        consume: bool,
    ) -> (bool, Vec<(bool, f64)>) {
        let slot = now.max(0) as u64 / self.slot_size;
        let frame = slot / u64::from(self.slots_per_frame);
        let mut updates = Vec::new();
        while self.pending.first().is_some_and(|first| slot > *first) {
            if let Some(next) = self
                .pending
                .range((std::ops::Bound::Excluded(slot), std::ops::Bound::Unbounded))
                .next()
                .copied()
            {
                // C++ upper_bound includes a current-slot opportunity in this
                // missed batch when an earlier opportunity was left pending.
                let missed = self.pending.range(..next).copied().collect::<Vec<_>>();
                for missed_slot in missed {
                    updates.push((
                        false,
                        (now - (missed_slot * self.slot_size) as i64) as f64
                            / self.slot_size as f64,
                    ));
                    self.pending.remove(&missed_slot);
                }
            } else {
                // Exhausting an entire batch refills without missed updates.
                self.pending.clear();
                self.refill(transponder, slot, frame);
            }
        }
        let available = self.pending.contains(&slot);
        if available && consume {
            updates.push((
                true,
                (now - (slot * self.slot_size) as i64) as f64 / self.slot_size as f64,
            ));
            self.pending.remove(&slot);
            if self.pending.is_empty() {
                self.refill(transponder, slot, frame);
            }
        }
        (available, updates)
    }
}
