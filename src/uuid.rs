fn get_uuid_v4() -> [u8; 16] {
    let mut bytes;
    let mut rand = rand::thread_rng();
    let buf: [u32; 4] = [rand.gen(), rand.gen(), rand.gen(), rand.gen()];
    bytes.copy_from_slice(&buf[..]);
    
    // Indicate that this is UUIDv4 as defined by RFC4122.
    bytes[6] = (bytes[6] & 0b00001111) | 0b01000000;
    bytes[8] = (bytes[8] & 0b00111111) | 0b10000000;

    bytes
}