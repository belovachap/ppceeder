use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use hickory_server::authority::{Authority, LookupError, LookupOptions, LookupRecords, MessageRequest, ZoneType};
use hickory_server::server::RequestInfo;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{LowerName, Name, RData, RecordSet, RecordType};

use crate::AppState;

pub struct SeederAuthority {
    origin: LowerName,
    state: Arc<AppState>,
}

impl SeederAuthority {
    pub fn new(origin: LowerName, state: Arc<AppState>) -> Self {
        Self { origin, state }
    }

    fn build_lookup(&self, name: &LowerName, lookup_options: LookupOptions) -> Result<LookupRecords, LookupError> {
        let nodes = self.state.good_nodes.lock().unwrap();
        let mut rdatas = Vec::new();
        for node in nodes.iter() {
            if let Ok(ip) = node.ip_address.parse::<Ipv4Addr>() {
                rdatas.push(RData::A(A(ip)));
            }
        }
        if rdatas.is_empty() {
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NXDomain));
        }
        let name: Name = name.clone().into();
        let mut record_set = RecordSet::new(&name, RecordType::A, 60);
        for rdata in rdatas {
            record_set.add_rdata(rdata);
        }
        Ok(LookupRecords::new(lookup_options, Arc::new(record_set)))
    }
}

#[async_trait]
impl Authority for SeederAuthority {
    type Lookup = LookupRecords;

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> Result<bool, hickory_proto::op::ResponseCode> {
        Err(hickory_proto::op::ResponseCode::NotImp)
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        if rtype != RecordType::A {
            self.state.dns_requests_non_a.fetch_add(1, Ordering::Relaxed);
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NXDomain));
        }
        self.state.dns_requests_a.fetch_add(1, Ordering::Relaxed);
        self.build_lookup(name, lookup_options)
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(request.query.name(), request.query.query_type(), lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(LookupRecords::new(lookup_options, Arc::new(RecordSet::new(&hickory_proto::rr::Name::root(), RecordType::A, 0))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use hickory_proto::rr::Name;
    use hickory_server::authority::LookupOptions;
    use std::sync::atomic::AtomicU64;

    #[tokio::test]
    async fn test_dns_requests_counter_increments() {
        let dns_requests_a = Arc::new(AtomicU64::new(0));
        let dns_requests_non_a = Arc::new(AtomicU64::new(0));
        let state = Arc::new(AppState::new(vec![], Arc::clone(&dns_requests_a), Arc::clone(&dns_requests_non_a)));
        let origin = LowerName::from(Name::from_ascii("example.com.").unwrap());
        let authority = SeederAuthority::new(origin, Arc::clone(&state));

        assert_eq!(dns_requests_a.load(Ordering::Relaxed), 0);
        assert_eq!(dns_requests_non_a.load(Ordering::Relaxed), 0);

        let name = LowerName::from(Name::from_ascii("example.com.").unwrap());
        let _ = authority.lookup(&name, RecordType::A, LookupOptions::default()).await;

        assert_eq!(dns_requests_a.load(Ordering::Relaxed), 1);
        assert_eq!(dns_requests_non_a.load(Ordering::Relaxed), 0);

        // Second call should increment again
        let _ = authority.lookup(&name, RecordType::A, LookupOptions::default()).await;

        assert_eq!(dns_requests_a.load(Ordering::Relaxed), 2);
        assert_eq!(dns_requests_non_a.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_dns_requests_counter_increments_on_non_a_record() {
        let dns_requests_a = Arc::new(AtomicU64::new(0));
        let dns_requests_non_a = Arc::new(AtomicU64::new(0));
        let state = Arc::new(AppState::new(vec![], Arc::clone(&dns_requests_a), Arc::clone(&dns_requests_non_a)));
        let origin = LowerName::from(Name::from_ascii("example.com.").unwrap());
        let authority = SeederAuthority::new(origin, Arc::clone(&state));

        let name = LowerName::from(Name::from_ascii("example.com.").unwrap());
        let _ = authority.lookup(&name, RecordType::AAAA, LookupOptions::default()).await;

        assert_eq!(dns_requests_a.load(Ordering::Relaxed), 0);
        assert_eq!(dns_requests_non_a.load(Ordering::Relaxed), 1);
    }
}
