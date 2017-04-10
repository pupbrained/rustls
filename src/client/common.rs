use msgs::handshake::CertificatePayload;
use msgs::handshake::DigitallySignedStruct;
use msgs::handshake::SessionID;
use msgs::handshake::SCTList;
use msgs::handshake::ServerExtension;
use msgs::persist;
use msgs::enums::ExtensionType;
use msgs::enums::NamedGroup;
use session::SessionRandoms;
use hash_hs;
use sign;
use suites;
use webpki;

use std::mem;

pub struct ServerCertDetails {
    pub cert_chain: CertificatePayload,
    pub ocsp_response: Vec<u8>,
    pub scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub fn new() -> ServerCertDetails {
        ServerCertDetails {
            cert_chain: Vec::new(),
            ocsp_response: Vec::new(),
            scts: None,
        }
    }

    pub fn take_chain(&mut self) -> CertificatePayload {
        mem::replace(&mut self.cert_chain, Vec::new())
    }
}

pub struct ServerKXDetails {
    pub kx_params: Vec<u8>,
    pub kx_sig: DigitallySignedStruct,
}

impl ServerKXDetails {
    pub fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> ServerKXDetails {
        ServerKXDetails {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

pub struct HandshakeDetails {
    pub transcript: hash_hs::HandshakeHash,
    pub resuming_session: Option<persist::ClientSessionValue>,
    pub randoms: SessionRandoms,
    pub using_ems: bool,
    pub session_id: SessionID,
    pub dns_name: webpki::DNSName,
}

impl HandshakeDetails {
    pub fn new(host_name: webpki::DNSName) -> HandshakeDetails {
        HandshakeDetails {
            transcript: hash_hs::HandshakeHash::new(),
            resuming_session: None,
            randoms: SessionRandoms::for_client(),
            using_ems: false,
            session_id: SessionID::empty(),
            dns_name: host_name,
        }
    }
}

pub struct ClientHelloDetails {
    pub sent_extensions: Vec<ExtensionType>,
    pub offered_key_shares: Vec<suites::KeyExchange>,
}

impl ClientHelloDetails {
    pub fn new() -> ClientHelloDetails {
        ClientHelloDetails {
            sent_extensions: Vec::new(),
            offered_key_shares: Vec::new(),
        }
    }

    pub fn has_key_share(&self, group: NamedGroup) -> bool {
        self.offered_key_shares
            .iter()
            .any(|share| share.group == group)
    }

    pub fn find_key_share(&mut self, group: NamedGroup) -> Option<suites::KeyExchange> {
        self.offered_key_shares.iter()
            .position(|s| s.group == group)
            .map(|idx| self.offered_key_shares.remove(idx))
    }

    pub fn find_key_share_and_discard_others(&mut self, group: NamedGroup)
            -> Option<suites::KeyExchange> {
        match self.find_key_share(group) {
            Some(group) => {
                self.offered_key_shares.clear();
                Some(group)
            }
            None => {
                None
            }
        }
    }

    pub fn server_sent_unsolicited_extensions(&self,
                                              received_exts: &[ServerExtension],
                                              allowed_unsolicited: &[ExtensionType]) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type) {
                debug!("Unsolicited extension {:?}", ext_type);
                return true;
            }
        }

        false
    }
}

pub struct ReceivedTicketDetails {
    pub new_ticket: Vec<u8>,
    pub new_ticket_lifetime: u32,
}

impl ReceivedTicketDetails {
    pub fn new() -> ReceivedTicketDetails {
        ReceivedTicketDetails::from(Vec::new(), 0)
    }

    pub fn from(ticket: Vec<u8>, lifetime: u32) -> ReceivedTicketDetails {
        ReceivedTicketDetails {
            new_ticket: ticket,
            new_ticket_lifetime: lifetime,
        }
    }
}

pub struct ClientAuthDetails {
    pub cert: Option<CertificatePayload>,
    pub signer: Option<Box<sign::Signer>>,
    pub auth_context: Option<Vec<u8>>,
}

impl ClientAuthDetails {
    pub fn new() -> ClientAuthDetails {
        ClientAuthDetails {
            cert: None,
            signer: None,
            auth_context: None,
        }
    }
}