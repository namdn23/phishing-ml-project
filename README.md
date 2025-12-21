🔍 ĐANG KIỂM TRA FILE: PhiUSIIL_Final_Dataset_Clean.csv
========================================
/home/kali/phishing_extractor/trichxuat18.py:8: DtypeWarning: Columns (11) have mixed types. Specify dtype option on import or set low_memory=False.
  df = pd.read_csv(filename)
📊 1. Kích thước: 235780 dòng x 25 cột
✅ Cấu trúc cột: Đầy đủ 25 cột theo yêu cầu.
✅ Dữ liệu trống: Không có ô nào bị bỏ trống.
🌐 2. Tỷ lệ trích xuất web thành công: 41.80%

⚖️ 3. Phân bố nhãn (Label):
   - Benign (0): 134844 mẫu (57.19%)
   - Phishing (1): 100936 mẫu (42.81%)

👀 4. Xem thử nội dung 3 dòng đầu:
                                URL  NoOfDegitsInURL  IsHTTPS  DomainTitleMatchScore  HasDescription  HasExternalFormSubmit  HasSocialNet  HasSubmitButton  HasPasswordField  HasCopyrightInfo  label V10_HTTP_Extraction_Success  V11_WHOIS_Extraction_Success  V1_PHash_Distance  V2_Layout_Similarity  V6_JS_Entropy  V7_Text_Readability_Score  V8_Total_IFrames  V9_Has_Hidden_IFrame  V5_TLS_Issuer_Reputation  V3_Domain_Age_Days  V4_DNS_Volatility_Count  Is_Top_1M_Domain  V22_IP_Subdomain_Pattern  V23_Entropy_Subdomain
0  https://www.southbankmosaics.com                0        1               0.000000               0                      0             0                1                 0                 1      0                           1                           1.0            0.50000                 0.425       0.706873                        1.0               0.0                   0.0                       1.0                 0.0                      1.0               0.0                       0.0                   -0.0
1          https://www.uni-mainz.de                0        1              55.555556               0                      0             1                1                 0                 1      0                           1                           1.0            0.40625                 0.200       0.619786                        1.0               0.0                   0.0                       1.0                 0.0                      1.0               0.0                       0.0                   -0.0
2    https://www.voicefmradio.co.uk                0        1              46.666667               1                      0             0                1                 0                 1      0                           1                           1.0            0.50000                 0.650       0.663223                        1.0               0.0                   0.0                       1.0                 0.0                      1.0               0.0                       0.0                   -0.0
