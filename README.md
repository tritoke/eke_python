# eke_python
An implementation of Bellovin and Merritt's EKE scheme in python, created to explore the algorithm for my final year project.

The implementation is derived from Bellovin and Merritt's original paper, using RSA as the asymmetric cipher and AES-128-ECB as the symmetric cipher.

The RSA version was chosen so I can implement a partition attack via a Machine-In-The-Middle (MITM) attack between the server and the client.

## Usage:
Running the server:
```
DEBUG=3 python3 server.py
```

Registering a user:
```
# will prompt for username and pass
python3 client.py register --debug 3
```
 
Using EKE to negotiate a shared key and then encrypting a message between them.
```
# will prompt for username and pass
python3 client.py negotiate --debug 3
```                                

## Example:
Client output:
```py
eke_python on  main [?]
➜ ./client.py --user tritoke --passwd beans --debug 3 register
[EKE.send_json] repr(data) = 'b\'{"action": "register", "username": "tritoke", "password": "beans"}\\n\''
[EKE.recv_json] received = '{"success": true, "message": "Successfully registered user tritoke"}'
Successfully registered user tritoke

eke_python on  main [?]
➜ ./client.py --user tritoke --passwd beans --debug 3 negotiate
[EKE.send_json] repr(data) = 'b\'{"action": "negotiate", "username": "tritoke", "enc_pub_key": "qRx8xbDG3uKf1GXu7EsDUfKP9rUE1nOYK/jUZEZa13clXPP0Mg8xfjLDccMusbHvZlz35Oxr5zmVQGEarfDg6a0qsfUC7jzo6lnN4Q1lkj2+OlV91NrGLlRz8LOP6GP2OSo0m4itf15OZ6OJhEPKsXEvZkshOBopF1OXIEZDn+Eg5hh36kg4SqIQi+pbWz06P0diS8//VItKo718CkC3iajbJbMgu0huWsyPU4ZXnlSwAzoifitJmefiG3pn7VKd47KYwu5671hd99aYwgUIssYfac4CArb9NYqC7xRR6WkZAPwTbP105qpuZzrp/IfbD06xSq82AO8Fk3MPVsfW1g==", "modulus": 18995388331159968634152936675636471121755329740331400798151855524152937855767717204698980697185808916396079081237447540832603564991162678891253305015269830289392698173186801274492880106373527936519379304794691633611679876456809669984547093184775127192859993152040100424800393342906250526079300171863826633363626364846444970552875663428054266845065032950612773587651953506929413442187422306075484400745066199076407488773486865219448555287713574621955250736192916710987094585178046348489705505272014365514071083182649334623876918783429788031460313408569837436625582780448779945508291825031615112292604994727145986064077}\\n\''
[EKE.recv_json] received = '{"enc_secret_key": "2GDZ/aYoAkc8WP0bUGSUqbql6k6swF2WmOsLbSGXwo4bZlSKbiMNFXkCIkpvyxhL3IiYwTSp0zRJAVOfoQTSS/0L/I5cgf0w7QAttILx597nay2eO3tDJiibu2IB7z8lPuxqsdwPM4KUDLAX1bo43Pl40fHRC5hMnbGfkzarfxoH1RM3bzCX/5I+wIuVpKd1WEqwy9gmmXSWkcg4mOzA99SH6fL2nDM5iiovjsm98o4N/s6x+kx2QgnvPVmGDo5kQUDurmwkJ+VLwTFwgHQX8MSXoiYcMEyts9KulxEKNtVz+gFSSSpCDGI3l2cLbDg3qSdH2ybzcOjDoSQxjAtm4g=="}'
[EKE.send_json] repr(data) = 'b\'{"challenge_a": "j14wdsd/TUWvW1lCyh9QNQ=="}\\n\''
[EKE.recv_json] received = '{"challenge_response": "j14wdsd/TUWvW1lCyh9QNRc7HfqFV91ZWamLIE3QB7Q="}'
[EKE.send_json] repr(data) = 'b\'{"challenge_b": "Fzsd+oVX3VlZqYsgTdAHtA=="}\\n\''
[EKE.recv_json] received = '{"success": true}'
message: I sure do love beans!
[EKE.send_json] repr(data) = 'b\'{"action": "send_message", "message": "Hyih5jg2MXVPAUKsit+6KfQBY5I43JF3RaLmIIwIotY="}\\n\''
```

Server output:
```py
[EKEHandler.recv_json()] received = '{"action": "register", "username": "tritoke", "password": "beans"}'
[EKEHandler.send_json()] repr(data) = 'b\'{"success": true, "message": "Successfully registered user tritoke"}\\n\''
[EKEHandler.recv_json()] received = '{"action": "negotiate", "username": "tritoke", "enc_pub_key": "qRx8xbDG3uKf1GXu7EsDUfKP9rUE1nOYK/jUZEZa13clXPP0Mg8xfjLDccMusbHvZlz35Oxr5zmVQGEarfDg6a0qsfUC7jzo6lnN4Q1lkj2+OlV91NrGLlRz8LOP6GP2OSo0m4itf15OZ6OJhEPKsXEvZkshOBopF1OXIEZDn+Eg5hh36kg4SqIQi+pbWz06P0diS8//VItKo718CkC3iajbJbMgu0huWsyPU4ZXnlSwAzoifitJmefiG3pn7VKd47KYwu5671hd99aYwgUIssYfac4CArb9NYqC7xRR6WkZAPwTbP105qpuZzrp/IfbD06xSq82AO8Fk3MPVsfW1g==", "modulus": 18995388331159968634152936675636471121755329740331400798151855524152937855767717204698980697185808916396079081237447540832603564991162678891253305015269830289392698173186801274492880106373527936519379304794691633611679876456809669984547093184775127192859993152040100424800393342906250526079300171863826633363626364846444970552875663428054266845065032950612773587651953506929413442187422306075484400745066199076407488773486865219448555287713574621955250736192916710987094585178046348489705505272014365514071083182649334623876918783429788031460313408569837436625582780448779945508291825031615112292604994727145986064077}'
[EKEHandler.send_json()] repr(data) = 'b\'{"enc_secret_key": "2GDZ/aYoAkc8WP0bUGSUqbql6k6swF2WmOsLbSGXwo4bZlSKbiMNFXkCIkpvyxhL3IiYwTSp0zRJAVOfoQTSS/0L/I5cgf0w7QAttILx597nay2eO3tDJiibu2IB7z8lPuxqsdwPM4KUDLAX1bo43Pl40fHRC5hMnbGfkzarfxoH1RM3bzCX/5I+wIuVpKd1WEqwy9gmmXSWkcg4mOzA99SH6fL2nDM5iiovjsm98o4N/s6x+kx2QgnvPVmGDo5kQUDurmwkJ+VLwTFwgHQX8MSXoiYcMEyts9KulxEKNtVz+gFSSSpCDGI3l2cLbDg3qSdH2ybzcOjDoSQxjAtm4g=="}\\n\''
[EKEHandler.recv_json()] received = '{"challenge_a": "j14wdsd/TUWvW1lCyh9QNQ=="}'
[EKEHandler.send_json()] repr(data) = 'b\'{"challenge_response": "j14wdsd/TUWvW1lCyh9QNRc7HfqFV91ZWamLIE3QB7Q="}\\n\''
[EKEHandler.recv_json()] received = '{"challenge_b": "Fzsd+oVX3VlZqYsgTdAHtA=="}'
[EKEHandler.send_json()] repr(data) = 'b\'{"success": true}\\n\''
[EKEHandler.recv_json()] received = '{"action": "send_message", "message": "Hyih5jg2MXVPAUKsit+6KfQBY5I43JF3RaLmIIwIotY="}'
[EKEHandler.receive_message] message="I sure do love beans!           "
```
