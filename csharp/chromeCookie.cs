 public class Program{
 
 
      private static void main(string[] args){
            //密钥位置C:\Users\3996\AppData\Local\Google\Chrome\User Data\Local State
            var encryptedKeyBytes = Convert.FromBase64String("RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAABJT/oYc86nRII9bd35dIS3AAAAAAIAAAAAABBmAAAAAQAAIAAAACpqXEXuHrk4VOPlhhRLti2OtRctUHA+Pz3SNH6E6zQoAAAAAA6AAAAAAgAAIAAAAKCjxocGnKJvPMEb4EvkfLuu5MPGFFKS47E+hYuEl1xEMAAAAOystXDUMBwp7a6ypPOGyrZX+i38WE7BPJCTnxAneYIwORBkXAMBDEQeh3EDv0CakUAAAAC7cOFpVK4xL4f4OjX6fJfihMPj1fSX0vVwLiqEiAereptAvGFynH7uVHq0UGCsEHoVvGWScOJTMqUdDe0zYsvP");
            encryptedKeyBytes = encryptedKeyBytes.Skip("DPAPI".Length).Take(encryptedKeyBytes.Length - "DPAPI".Length).ToArray();
            var keyBytes = ProtectedData.Unprotect(encryptedKeyBytes, null, DataProtectionScope.CurrentUser);
            
             var connString = "Data Source="+ Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)+ @"\Google\Chrome\User Data\Default\Cookies";
             //查找
             //string sql2 = "select * from cookies where host_key='.douyin.com' and name='sessionid'";
            //conn.Open();
            //SqliteCommand cmd = new SqliteCommand(sql2, conn);
            //SqliteDataReader dr = cmd.ExecuteReader();
            //dr.Read();
            //byte[] encryptedValue = (byte[])dr["encrypted_value"];
            //cmd.Dispose();
            //conn.Dispose();
            //var str= Decrypt(keyBytes, encryptedValue);
            
            //修改
             var b = Encrypt(keyBytes, "638307754ad7214255403a6f9a6e27f3");
            using SqliteConnection conn = new SqliteConnection(connString);
            string sql2 = "UPDATE cookies SET encrypted_value=@value where host_key='.douyin.com' and name='sessionid'";
            conn.Open();
            using SqliteCommand cmd = new SqliteCommand(sql2, conn);
            cmd.Parameters.Add("@value", SqliteType.Blob).Value = b;
            cmd.ExecuteNonQuery();
            cmd.Dispose();
            conn.Dispose();

}
 
 
        private byte[] Encrypt(byte[] key,string data)
        {
            var nonce = new byte[12]; //取值范围为 AesGcm.NonceByteSizes
            var tag = new byte[16]; //取值范围为 AesGcm.TagByteSizes
            Random rnd =new Random();
            rnd.NextBytes(nonce);
            rnd.NextBytes(tag);
            byte[] dataToEncrypt = System.Text.Encoding.Default.GetBytes(data);
            byte[] ciphertext = new byte[dataToEncrypt.Length];
            using (AesGcm aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, dataToEncrypt, ciphertext, tag);
            }
            return Encoding.Default.GetBytes("v10").Concat(nonce).Concat(ciphertext).Concat(tag).ToArray();
        }

        private string Decrypt(byte[] key, byte[] encryptedValue)
        {
            encryptedValue = encryptedValue.Skip("v10".Length).ToArray();
            var nonce = encryptedValue.Take(12).ToArray();
            encryptedValue = encryptedValue.Skip(12).Take(encryptedValue.Length - 12).ToArray();
            using var gcm = new AesGcm(key);
            byte[] ciphertext = encryptedValue.Take(encryptedValue.Length - 16).ToArray();
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] tag = encryptedValue.Skip(ciphertext.Length).Take(16).ToArray();
            gcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
 
 
 }
