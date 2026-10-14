//! Storage-independent evidence receipts shared by Python and WebAssembly.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
struct State {
    version: u32,
    ips: BTreeMap<String, BTreeSet<String>>,
}

pub struct ReceiptLedger {
    state: State,
    seen: BTreeMap<String, BTreeSet<String>>,
    fresh_ips: BTreeSet<String>,
    acted: BTreeSet<String>,
    pub had_history: bool,
}

impl ReceiptLedger {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let state: State = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if state.version != 1
            || state
                .ips
                .values()
                .flatten()
                .any(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("Invalid AIWAF training evidence state".into());
        }
        let had_history = !state.ips.is_empty();
        Ok(Self {
            state,
            seen: BTreeMap::new(),
            fresh_ips: BTreeSet::new(),
            acted: BTreeSet::new(),
            had_history,
        })
    }

    pub fn observe(
        &mut self,
        records: Vec<(String, String, String, String)>,
    ) -> Result<Vec<usize>, String> {
        let mut indices = Vec::new();
        for (index, (ip, timestamp, path, status)) in records.into_iter().enumerate() {
            let bytes =
                serde_json::to_vec(&(&ip, timestamp, path, status)).map_err(|e| e.to_string())?;
            let receipt = format!("{:x}", Sha256::digest(bytes));
            self.seen
                .entry(ip.clone())
                .or_default()
                .insert(receipt.clone());
            if !self
                .state
                .ips
                .get(&ip)
                .is_some_and(|s| s.contains(&receipt))
            {
                indices.push(index);
                self.fresh_ips.insert(ip);
            }
        }
        Ok(indices)
    }

    pub fn can_block(&self, ip: &str) -> bool {
        self.fresh_ips.contains(ip) && !self.acted.contains(ip)
    }

    fn next_state(&self, ip: &str) -> Result<State, String> {
        if !self.can_block(ip) {
            return Err("No fresh training evidence for this IP".into());
        }
        let mut state = self.state.clone();
        state
            .ips
            .entry(ip.into())
            .or_default()
            .extend(self.seen.get(ip).cloned().unwrap_or_default());
        Ok(state)
    }

    pub fn committed_state(&self, ip: &str) -> Result<String, String> {
        serde_json::to_string(&self.next_state(ip)?).map_err(|e| e.to_string())
    }

    pub fn commit(&mut self, ip: &str) -> Result<(), String> {
        self.state = self.next_state(ip)?;
        self.acted.insert(ip.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(stamp: &str) -> (String, String, String, String) {
        (
            "ip".into(),
            stamp.into(),
            "/missing.php".into(),
            "404".into(),
        )
    }
    #[test]
    fn receipts_survive_restart_and_do_not_replay_rotated_copies() {
        let mut ledger = ReceiptLedger::from_json(r#"{"version":1,"ips":{}}"#).unwrap();
        assert_eq!(
            ledger.observe(vec![row("1"), row("2")]).unwrap(),
            vec![0, 1]
        );
        let state = ledger.committed_state("ip").unwrap();
        ledger.commit("ip").unwrap();
        assert!(!ledger.can_block("ip"));
        let mut next = ReceiptLedger::from_json(&state).unwrap();
        assert_eq!(
            next.observe(vec![row("2"), row("1"), row("2"), row("3")])
                .unwrap(),
            vec![3]
        );
        assert!(next.can_block("ip"));
    }
    #[test]
    fn validates_state_and_keeps_uncommitted_evidence_fresh() {
        assert!(ReceiptLedger::from_json(r#"{"version":2,"ips":{}}"#).is_err());
        assert!(ReceiptLedger::from_json(r#"{"version":1,"ips":{"ip":["broken"]}}"#).is_err());
        let mut ledger = ReceiptLedger::from_json(r#"{"version":1,"ips":{}}"#).unwrap();
        assert!(ledger.committed_state("ip").is_err());
        ledger.observe(vec![row("1")]).unwrap();
        assert_eq!(ledger.observe(vec![row("1")]).unwrap(), vec![0]);
    }
}
