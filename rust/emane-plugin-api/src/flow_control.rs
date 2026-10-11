//! Token producer handshake shared by native MACs and the legacy FFI.
#[derive(Debug)]
pub struct FlowControlManager {
    tokens_available: u16,
    total_tokens_available: u16,
    shadow_token_count: u16,
    last_tokens_update: u16,
    ack_pending: bool,
}

impl FlowControlManager {
    pub fn new() -> Self {
        Self {
            ack_pending: true,
            tokens_available: 0,
            total_tokens_available: 0,
            shadow_token_count: 0,
            last_tokens_update: 0,
        }
    }

    pub fn start(&mut self, total_tokens: u16) -> u16 {
        self.total_tokens_available = total_tokens;
        self.tokens_available = total_tokens;
        self.update_shadow_and_ack()
    }

    pub fn stop(&mut self) {
        self.total_tokens_available = 0;
        self.tokens_available = 0;
        self.shadow_token_count = 0;
    }

    pub fn add_token(&mut self, tokens: u16) -> (u16, bool, Option<u16>) {
        let status =
            (self.tokens_available as u32 + tokens as u32) <= self.total_tokens_available as u32;
        if status {
            self.tokens_available += tokens;
        }

        let mut send_update = None;
        if self.shadow_token_count == 0 && self.tokens_available > 0 {
            send_update = Some(self.update_shadow_and_ack());
        }

        (self.tokens_available, status, send_update)
    }

    pub fn remove_token(&mut self) -> (u16, bool) {
        if self.ack_pending {
            return (self.tokens_available, false);
        }

        if self.tokens_available == 0 {
            return (self.tokens_available, false);
        }

        self.tokens_available -= 1;
        self.shadow_token_count = self.shadow_token_count.wrapping_sub(1);
        (self.tokens_available, true)
    }

    pub fn process_flow_control_message(&mut self, tokens: u16) -> Option<u16> {
        if !self.ack_pending {
            Some(self.update_shadow_and_ack())
        } else {
            if tokens == self.last_tokens_update {
                self.ack_pending = false;
                None
            } else {
                Some(self.update_shadow_and_ack())
            }
        }
    }

    fn update_shadow_and_ack(&mut self) -> u16 {
        let tokens = self.tokens_available;
        self.shadow_token_count = tokens;
        self.last_tokens_update = tokens;
        self.ack_pending = true;
        tokens
    }
}

impl Default for FlowControlManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_require_echo_and_replenish_only_after_shadow_exhaustion() {
        let mut manager = FlowControlManager::new();
        assert_eq!(manager.start(2), 2);
        assert_eq!(manager.remove_token(), (2, false));
        assert_eq!(manager.process_flow_control_message(0), Some(2));
        assert_eq!(manager.process_flow_control_message(2), None);
        assert_eq!(manager.remove_token(), (1, true));
        assert_eq!(manager.add_token(1), (2, true, None));
        assert_eq!(manager.remove_token(), (1, true));
        assert_eq!(manager.add_token(1), (2, true, Some(2)));
        assert_eq!(manager.remove_token(), (2, false));
        assert_eq!(manager.process_flow_control_message(2), None);
        assert_eq!(manager.process_flow_control_message(2), Some(2));
        assert_eq!(manager.remove_token(), (2, false));
    }
    #[test]
    fn partial_return_keeps_outstanding_grant_and_rejects_overflow() {
        let mut manager = FlowControlManager::new();
        manager.start(3);
        manager.process_flow_control_message(3);
        for remaining in (0..3).rev() {
            assert_eq!(manager.remove_token(), (remaining, true));
        }
        assert_eq!(manager.remove_token(), (0, false));
        assert_eq!(manager.add_token(1), (1, true, Some(1)));
        assert_eq!(manager.add_token(2), (3, true, None));
        assert_eq!(manager.add_token(u16::MAX), (3, false, None));
        assert_eq!(manager.process_flow_control_message(1), None);
        assert_eq!(manager.remove_token(), (2, true));
        assert_eq!(manager.add_token(1), (3, true, Some(3)));
    }
    #[test]
    fn shadow_wrap_and_same_instance_restart_match_unsigned_cpp_state() {
        let mut manager = FlowControlManager::new();
        manager.start(2);
        manager.process_flow_control_message(2);
        manager.remove_token();
        manager.add_token(1);
        manager.remove_token();
        assert_eq!(manager.remove_token(), (0, true)); // sender exceeds its grant
        assert_eq!(manager.add_token(1), (1, true, None));
        manager.stop();
        assert_eq!(manager.remove_token(), (0, false));
        manager.start(u16::MAX);
        assert_eq!(manager.remove_token(), (u16::MAX, false));
        manager.process_flow_control_message(u16::MAX);
        assert_eq!(manager.remove_token(), (u16::MAX - 1, true));
    }
}
