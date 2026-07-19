#![no_main]

use libfuzzer_sys::fuzz_target;
use proteus_wire::{alpha, varint, AuthExtension, InnerHeader};

fuzz_target!(|data: &[u8]| {
    let _ = AuthExtension::decode_payload(data);
    let _ = InnerHeader::decode_wire(data);
    let _ = varint::decode(data);
    let _ = alpha::decode_pcs_control(data);

    if let Ok((frame, consumed)) = alpha::decode_frame(data) {
        assert!(consumed <= data.len());
        assert!(consumed >= frame.body.len() + 2);
    }

    if data.len() >= 40 {
        let generation = u64::from_be_bytes(data[..8].try_into().unwrap());
        let mut value = [0_u8; 32];
        value.copy_from_slice(&data[8..40]);
        let control = alpha::PcsControl { generation, value };
        let encoded = alpha::encode_pcs_control(control);
        assert_eq!(alpha::decode_pcs_control(&encoded).unwrap(), control);
    }
});
