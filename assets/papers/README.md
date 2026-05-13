# assets/papers/ — 論文 PDF 本機暫存

這個資料夾**整個被 `.gitignore` 擋住**，PDF 不會上 git。

## 為什麼

- 論文絕大多數有版權，未經授權重新分發違法
- 重新下載成本極低（USENIX / ACM / arXiv / IACR ePrint 都有公開鏡像）
- 我們真正要長期保留的是 [`notes/papers/`](../../notes/papers/) 裡的**讀書筆記**

## 命名慣例

```
assets/papers/{venue}-{year}-{shortid}.pdf

例：
  assets/papers/usenix-sec-2023-fep-detection.pdf
  assets/papers/sigcomm-2017-quic.pdf
  assets/papers/cacm-2017-bbr.pdf
  assets/papers/imc-2020-shadowsocks-detection.pdf
  assets/papers/ndss-2020-flowprint.pdf
  assets/papers/iacr-2018-noise-framework.pdf
```

`shortid` 是論文的識別關鍵字（標題核心詞 / 主協議名 / 主作者姓），方便 grep。

## 對應的筆記在哪

每個 PDF 都應該有一份 `notes/papers/{shortid}.md` 的精讀筆記（commit 進 git）。
