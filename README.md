import pandas as pd

# 1. Đọc file đã gộp
df = pd.read_csv('PhiUSIIL_Final_Dataset_Clean.csv', low_memory=False)

# 2. Lọc: Chỉ giữ lại những dòng trích xuất THÀNH CÔNG (V10 = 1)
df_clean = df[df['V10_HTTP_Extraction_Success'] == 1].copy()

# 3. Chuyển đổi các cột số về đúng định dạng (tránh lỗi DtypeWarning)
cols_to_fix = ['V1_PHash_Distance', 'V2_Layout_Similarity', 'V6_JS_Entropy']
for col in cols_to_fix:
    df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')

# 4. Xóa bỏ các cột không dùng để Train (như URL)
# Chúng ta giữ lại 'label' làm mục tiêu và các cột còn lại làm tính năng
X_data = df_clean.drop(columns=['URL'])

# 5. Lưu file sẵn sàng để Train
X_data.to_csv('Dataset_Ready_to_Train.csv', index=False)

print(f"✅ Đã lọc xong! Còn lại {len(X_data)} mẫu chất lượng cao.")
print(f"📊 Phân bố nhãn mới:\n{X_data['label'].value_counts()}")
