# csa-attack

# How to use
> sudo ./csa-attack <interface> <ap mac> [<station mac>]
> sudo ./csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB

# Demonstration
> 2.4GHz 기준 가장 멀리 떨어진 채널로 이동하도록 구현
> 공격 대상의 채널은 11번인 상태

## Broadcast
> sudo ./csa-attack mon0 00:11:22:33:44:55
![broadcast](https://github.com/S-SIRIUS/csa-attack/assets/109223193/8a2ea25c-8096-4f6e-8cff-740df1c88382)


## Unicast
> sudo ./csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
![unicast](https://github.com/S-SIRIUS/csa-attack/assets/109223193/8d667b1a-5538-4f52-8cb5-2d3deb16e081)


## Result
![KakaoTalk_20240131_1839295218](https://github.com/S-SIRIUS/csa-attack/assets/109223193/a4bf87c1-97be-4750-863c-737f0d70c19b)

