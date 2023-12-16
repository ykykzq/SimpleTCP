///查表法生成CRC32校验码
pub struct Crc32Table(
    Vec<u32>
);
impl Crc32Table{
    ///生成CRC32校验码辅助计算表
    pub fn new() -> Self{
        let mut new_crc32_table:Crc32Table=Crc32Table(vec![0 as u32;256]);
        let mut crc:u32;
        for i in 0..256{
            crc=i;
            for _ in 0..8{
                if (crc & 1)==1 {
                    crc=(crc >> 1) ^ 0xEDB88320;
                }
                else{
                    crc >>= 1;
                }
            }
            new_crc32_table.0[i as usize] = crc;
        }
        new_crc32_table
    }
}


//根据crc32表计算crc32码
pub fn calculate_crc32(buffer: &Vec<u8>,len: i32)-> u32{
    let mut crc:u32=0xffff_ffff;
    let crc32_table=Crc32Table::new();
    for i in 0..len{
        crc=(crc >> 8) ^ crc32_table.0[((crc & 0xFF) ^ buffer[i as usize]as u32) as usize] as u32;
    }
    crc = crc ^0xffff_ffff as u32;
    crc
}
