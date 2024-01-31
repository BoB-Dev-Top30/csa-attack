# csa-attack

# How to use
`sudo ./csa-attack <interface> <ap mac> [<station mac>]`

`sudo ./csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB`

# Demonstration

2.4GHz 기준 가장 멀리 떨어진 채널로 이동하도록 구현</br>
공격 대상의 채널은 11번인 상태

## Broadcast
> sudo ./csa-attack mon0 00:11:22:33:44:55

![broadcast](https://github.com/BoB-Dev-Top30/csa-attack/assets/109223193/8c6473b5-d1d0-48fe-9567-58107f65dc94)


## Unicast
> sudo ./csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB

![unicast](https://github.com/BoB-Dev-Top30/csa-attack/assets/109223193/1e19da56-7028-493b-b4f2-d446c338e021)


## Result

![KakaoTalk_20240131_1839295218](https://github.com/BoB-Dev-Top30/csa-attack/assets/109223193/6737c13a-7479-4362-ab59-a8888529482d)


