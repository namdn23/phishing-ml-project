import pandas as pd
import numpy as np

def check_merged_file(filename):
    print(f"🔍 ĐANG KIỂM TRA FILE: {filename}\n" + "="*40)
    
    try:
        df = pd.read_csv(filename)
    except Exception as e:
        print(f"❌ Không thể mở file: {e}")
        return

    # 1. Kiểm tra số lượng cột và tên cột
    expected_cols = [
        'URL', 'NoOfDegitsInURL', 'IsHTTPS', 'DomainTitleMatchScore', 'HasDescription', 
        'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 'HasPasswordField', 
        'HasCopyrightInfo', 'label', 'V10_HTTP_Extraction_Success', 
        'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 'V2_Layout_Similarity', 
        'V6_JS_Entropy', 'V7_Text_Readability_Score', 'V8_Total_IFrames', 
        'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V3_Domain_Age_Days', 
        'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 'V22_IP_Subdomain_Pattern', 
        'V23_Entropy_Subdomain'
    ]
    
    print(f"📊 1. Kích thước: {df.shape[0]} dòng x {df.shape[1]} cột")
    missing_cols = [c for c in expected_cols if c not in df.columns]
    if not missing_cols:
        print("✅ Cấu trúc cột: Đầy đủ 25 cột theo yêu cầu.")
    else:
        print(f"❌ Thiếu cột: {missing_cols}")

    # 2. Kiểm tra dữ liệu trống (NaN)
    null_counts = df.isnull().sum().sum()
    if null_counts == 0:
        print("✅ Dữ liệu trống: Không có ô nào bị bỏ trống.")
    else:
        print(f"⚠️ Cảnh báo: Có {null_counts} ô bị trống (NaN). Cần xử lý trước khi train!")

    # 3. Kiểm tra tỷ lệ trích xuất thành công (V10)
    v10_counts = df['V10_HTTP_Extraction_Success'].value_counts()
    success_rate = (v10_counts.get(1, 0) / len(df)) * 100
    print(f"🌐 2. Tỷ lệ trích xuất web thành công: {success_rate:.2f}%")

    # 4. Kiểm tra sự cân bằng nhãn (Label balance)
    print("\n⚖️ 3. Phân bố nhãn (Label):")
    label_counts = df['label'].value_counts()
    for lbl, count in label_counts.items():
        name = "Phishing (1)" if lbl == 1 else "Benign (0)"
        print(f"   - {name}: {count} mẫu ({count/len(df)*100:.2f}%)")

    # 5. Xem thử 3 dòng đầu
    print("\n👀 4. Xem thử nội dung 3 dòng đầu:")
    print(df.head(3).to_string())

if __name__ == "__main__":
    check_merged_file('PhiUSIIL_Final_Merged.csv')
