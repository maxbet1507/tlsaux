# tlsaux
addons for golang crypto/tls

__deplicated this package__

go1.11からcrypt/tlsのConn.ConnectionState()から、
ExportKeyingMaterialでPRFをコールできるようになりました。

```golang
cs := conn.ConnectionState()
ret, _ := cs.ExportKeyingMaterial("label", nil, 128)
```

どうしても、

* MasterSecret
* ClientRandom
* ServerRandom

の生値が必要な場合以外か、go1.11未満の環境でない限り非推奨です。
