#ifndef NETSRV_H
#define NETSRV_H

#ifdef _TLS
#ifdef _TLS_TWOWAY
const char *s_tls_ca = 
  "-----BEGIN CERTIFICATE-----\n" 
  "MIIE/zCCAuegAwIBAgIUM/ZzetB39SDPm+duWsSgYmoxmj0wDQYJKoZIhvcNAQEL\n" 
  "BQAwDzENMAsGA1UEAwwETXlDQTAeFw0yNDAzMjMwMTU5NTlaFw0yNTAzMjMwMTU5\n" 
  "NTlaMA8xDTALBgNVBAMMBE15Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n" 
  "AoICAQCxvPU3GeucniEqxHKyMU9XYOW5VhfzbD+EiE1xD4Ogu6YHjDvc3lKoyloo\n" 
  "Fc4sckNuYLxFZ2FUoIV4RzGYyc4Tfx4e/aBNGXB5U2YrXxtE9daYv1XmVGmMsZ6c\n" 
  "yiGCRjdfRrBkJ6ylTbihpuk3JkwmpzKmIaWYo+TCoQGtpX1fWa0K8Kj+xqkb/T9M\n" 
  "6kFuIEFeP7ngQAWFZcnK62Y+MYYOYCH9WNIQZoBU/Oumv9JLFzTg1svA/7wa6uEk\n" 
  "KIvVSGBOqBYv58TNXr6pW9y38Qvms39HpQ1C874ZwoDpbfB2gMZ27gbU2rqelgPz\n" 
  "Mb/r/JhYTQkP82ml0BBJ+lqIFiQqfxKa5np1dKJEWP8FwQAuZcTmqdY+G8eJrEyJ\n" 
  "ITGf+r/+Nsm/vtyRL5yDDRJX6SNB6NvAoXaJVoPijgY3L3bjM8kGl+tZHqPriOZD\n" 
  "d+Q/HIwFir7RCz8dGf5O7qJJL3y+LShBs6ENxXfRnyDJEdaxrhdNSfz0gOu92wjB\n" 
  "KdTA6GCArZCBnERFYsXEWDl03tMVvcYuolho0jOoRpnuy8hQ3tsjPQnOX9zuhelx\n" 
  "hgMX/uPuPq5YQJjco5DobpwhU71VnaXakHFw58gjmr89u79up/aqdefeTF87BvxI\n" 
  "+8ouc3JDCrrx6mzNQ98fia8W2huEu0h6FEvW5ediBmrI7QqbswIDAQABo1MwUTAd\n" 
  "BgNVHQ4EFgQUo0lAoLQDKr8AfH2HzRY1T+Y362kwHwYDVR0jBBgwFoAUo0lAoLQD\n" 
  "Kr8AfH2HzRY1T+Y362kwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n" 
  "AgEAaO6972WFJmpdwaU1OOW2L9WSAiyPXpH9Ge7FS/EUmmYYZRCdz4u8vpWbYH5E\n" 
  "yLtr6HgoS9tpw2A7WaMqePXnd+d3HOxZLN1v9lPqJ+TpygHQipykhuy8h1zMybW/\n" 
  "rrQjUTa6jNgZ2gxiE+jxF3YItdkN7ypWo9KTy+vV+XMF6CP5lxpzhfS2EpN7SctM\n" 
  "XTYd9l6mSp1DE5oYnPXIJmG2oNOIaTiHyRUflTCNZ9prqtj624bmccv+BveWCRqg\n" 
  "dYLpgYVkzmZKl1VwWttn9a5PmueJX478L8seeqbWbCJ15pJLgPQG07fwJaBqZAH8\n" 
  "b6yywwL2tm0tywACeGih6X3q33ZwkrA0jukwCydtqQ/sLa6BL7IU4WKjFdw2nt6a\n" 
  "D+x5K7TXYamVwjuTW6rN9fdxANQ58IWEjZxkyOVU0aqy7XSkJlsM5c6n7wX4wXi5\n" 
  "GSbKbPmemAwzXtPhBGpcZTNKYmLZItyQ9bhrFyD5c/Io+ajTGHZiSXpcokF5QU79\n" 
  "gbAJA5WZB376GO8NUOQ1z4fZH1au/PkjldvomZbj/AcGY2iIolxdFAWbZyGAbKuX\n" 
  "dwHuIv9Y+erKkNURswAM7kLUsHhwao8M6y29nkmFIHbcHuehpUUWGoPqHrTwqgSx\n" 
  "uekHZ8/YfEtnFRLjRRc1HvhWltfnfJOXecjB5lSXsC6300k=\n" 
  "-----END CERTIFICATE-----\n" 
;
#endif

const char *s_tls_cert = 
  "-----BEGIN CERTIFICATE-----\n" 
  "MIIDljCCAX4CAQEwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwETXlDQTAeFw0y\n" 
  "NDAzMjMwMTU5NTlaFw0yNTAzMjMwMTU5NTlaMBMxETAPBgNVBAMMCE15U2VydmVy\n" 
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMpqYa6cNXC9UVCboIjB\n" 
  "Tp80ilWEqLR9poQndBhRcyQdygpwcYLffPHq/D1bI5Sgl7XJLbKba1rMz9QO07xL\n" 
  "aqHVQy8kp4Zxpb1qwmTZ7TXEpkt1OtQsg36ybpjApnUSKZ9YQNzgOfau3MoggjTm\n" 
  "kKx7KodrB8sLoyWs9HSSRdAyvq6AbcahKhPhgw8U7uR98PWxnbny17fHu++do6LW\n" 
  "5KuKCvLMzSV1v+yIwy5ughjD3Hy6JpLBhreKBvsCoQv87Y7664ls+nsv/UUhNZmh\n" 
  "PdFhb02fmCbUBo1Y5VQoZEREMmDhTQxdpD1y6KU/puL3O4z1asavwyW1mvlgn1Xr\n" 
  "jQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAf8dHYUSXP74776OYk7Kt18q5Bevrf\n" 
  "ggVUVwI0orrCu/fQZn5NLcqRMA/yh3QfVIrQjcdaVyhoBT8U+WtMHCN1qEvzOkZa\n" 
  "Uq2eHmp2KCFkXQurX+3SKuvRqvKRSI9eJz2vB9ZauDf9uvq6chqds134TrJvKGcx\n" 
  "9wIB+NMcCrATyO/T3Ua9nA68XIp4XS/6YkN85ZuM9pV8DT4NVcfY+ebrRgTj9ifB\n" 
  "2aQdP/C5Bk/fnZMgvUVW2vriN8gMJYigqDnHcWSAEXjIhAEpjLpsi9yl8gAy9gIL\n" 
  "0iMXqRw/qGp2athwG20dX13GOW8+0geJHLqUJRFzgIrPHgBf8RcI9nxvMByMQO5d\n" 
  "Rrt10FA4PuUWCtZr00B+iNkg6ErCmjTEmkgEReSQ3NyKFCp60nCNleObFfXidv5b\n" 
  "JaZkhOWFho5AZwQzxAgDhJ1QWdKJfOySHZ7VOxbej99MRx6po1X2hEMrcLP8QJ3e\n" 
  "VadBAN4u4RXH5abaRjP1R0TDKS6Y5SbJS0F0NP/kvNMFiTuiQClbS0eyXf2p1K84\n" 
  "DUhNOMxFCJRqg2KrJS4jiXjUswC56dZSHa6UPuQ7Mv0shxp3pc/m56vU4omz0a98\n" 
  "sVGQAnKKz6aXNRXpnuWgK3587ZFjKZpynB4256dsUYB0ref4qwPCIhstWt9C+r/J\n" 
  "v8Xg/q7FC3RNXg==\n" 
  "-----END CERTIFICATE-----\n" 
;
const char *s_tls_key = 
  "-----BEGIN RSA PRIVATE KEY-----\n" 
  "MIIEpQIBAAKCAQEAxMpqYa6cNXC9UVCboIjBTp80ilWEqLR9poQndBhRcyQdygpw\n" 
  "cYLffPHq/D1bI5Sgl7XJLbKba1rMz9QO07xLaqHVQy8kp4Zxpb1qwmTZ7TXEpkt1\n" 
  "OtQsg36ybpjApnUSKZ9YQNzgOfau3MoggjTmkKx7KodrB8sLoyWs9HSSRdAyvq6A\n" 
  "bcahKhPhgw8U7uR98PWxnbny17fHu++do6LW5KuKCvLMzSV1v+yIwy5ughjD3Hy6\n" 
  "JpLBhreKBvsCoQv87Y7664ls+nsv/UUhNZmhPdFhb02fmCbUBo1Y5VQoZEREMmDh\n" 
  "TQxdpD1y6KU/puL3O4z1asavwyW1mvlgn1XrjQIDAQABAoIBAQC6SLpHWZj5ZY1w\n" 
  "6hNH9ey3VjHQOX/oi2LeO/91AIgprKieVx919GNGzWKaACLEHa+frS+RmJ9TEpMK\n" 
  "sTyP5pClkihk/r197+Co+hOTjRBWYi2TFZ8VXz/8AfU6iFLlv7C/wd0zGWMQu5lv\n" 
  "287GMvmHPh8hdSs2J1kOyV1d0vOcLP6vMQyFOi5TtVcSY43/UCf2ApMdxf7VPJWy\n" 
  "LVfMwvE7pIK9AmLp8ky1kiHX/ME8U/xGd+P/K12IYPYET8gPKPp25Go+DzMvar/N\n" 
  "llD1YCtUL5wm5wvTLb8XeFnN/f5FJ42SU6oZKOvVKfVzQYLcgpqvGrKKtAZ6qc0F\n" 
  "FlsTp4VpAoGBAOWWh7dq4Zc7pV9KK3pplnp5wpVK25g0G2Z1/RQoZUWGgVn/o81g\n" 
  "YuaHDbFjYUMKtpych6n14CTub+Uw0MfeslKgHu2vQkgZgNbu+p1ArDUG1EwjlONJ\n" 
  "CPXkqUDROZlAArSjnW7hSraqhNm248wuCYT7ajFpLHGFg9ch/gFDFnAzAoGBANtt\n" 
  "/VLC1xfSVv4eEo2osWhREYyc2AvXsq8arDBB+mNt3w8Zo7C/YDbEV8IuFTanJ6/A\n" 
  "r949GKpcplys4EGdETBbSnZ77WmIdNm4A37/enaz8Yksk/19iIlkzOf2S3LpXyL0\n" 
  "9JEtLY5jsMfAt/FwB3XK0mY61bN/IqAgLqGZU3U/AoGBALT9BeBCEbT3AFcuUTgf\n" 
  "JNFIS20FpjdGXJNZUDkj3zH/5tjb/nVZFp5EuTat8W64c1ziyM/jVN/IV82FvhDS\n" 
  "LiGUuM0G7GmKMVc+7bIp2Zez2ohrRGQonze5GvRN++oj2/4rPWC7mfqGUlSPKOU9\n" 
  "JaP/zqdFEhQr/NMLqQG1sWqhAoGAPDr7ruzmZ5aH5GbSxumIEM831vXyY4XIeUIE\n" 
  "A5cIqKQu9xEdmlVdjorkX9uQXRkSzq5AV+tDSvf1fjjBsaDwZ+qXDODFcRNQp7ZX\n" 
  "11M/BTgtU27WDF2ZzcTKbd1wJlGimJDOVM8m0w/QJXRjyTTsB0wt5nu9zvBVy8gp\n" 
  "pJfWjbcCgYEAijOsZ4NYSAzh5KRYNCgevStprtCl6byhzgfgpN0UHCpmk8e61xCV\n" 
  "UFf2v3G59ssHXwwNmWCv4hQDkCj4aW36T8W6tKgkjxvI/ajx2sbxX8SpmlX5VlyP\n" 
  "SCJCyGternmn0mv9q0za+kTKNKWTIFKrsf4+w4YB4n/UIiQEqdY39OE=\n" 
  "-----END RSA PRIVATE KEY-----\n" 
;
#endif
#endif /* NETSRV_H */
