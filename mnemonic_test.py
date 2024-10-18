from mnemonic import Mnemonic

# 生成指定語言的助記詞
def generate_chinese_mnemonic(strength=128, language="chinese_traditional"):
    mnemo = Mnemonic(language)
    mnemonic_phrase = mnemo.generate(strength=strength)
    return mnemonic_phrase

# 從用戶輸入獲取助記詞
def input_mnemonic():
    mnemonic_phrase = input("請輸入您的助記詞（單詞之間用空格分隔）: ")
    return mnemonic_phrase.strip()

# 驗證助記詞的有效性
def validate_mnemonic(mnemonic_phrase, language="chinese_traditional"):
    mnemo = Mnemonic(language)
    return mnemo.check(mnemonic_phrase)

# 將助記詞轉換為種子
def mnemonic_to_seed(mnemonic_phrase, passphrase=""):
    mnemo = Mnemonic("chinese_traditional")
    return mnemo.to_seed(mnemonic_phrase, passphrase)

if __name__ == "__main__":
    # 生成繁體中文助記詞（12個單詞）
    chinese_mnemonic = generate_chinese_mnemonic()
    print("生成的繁體中文助記詞:", chinese_mnemonic)

    # 示例繁體中文助記詞
    mnemonic_phrase = "濃 潮 度 律 榮 巨 逼 磁 刻 朗 畫 窩"
    mnemo = Mnemonic("chinese_traditional")

    # 驗證助記詞
    is_valid = mnemo.check(mnemonic_phrase)
    print("助記詞有效性:", is_valid)  # 輸出應為 True 或 False

    # 將助記詞轉換為種子
    seed = mnemonic_to_seed(mnemonic_phrase, '1234')
    print("種子:", seed.hex())
