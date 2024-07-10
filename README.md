# pktweak, a library to sign with tweaked private key


## Usage

Follow the example [here](./test/).

Basically:

1. Call `Tweaker.Tweak` to convert your private key to tweaked version.
2. Call `Tweaker.Initialize` to initialize `Tweaker` for signing.
3. Call `Tweaker.Sign` to get the expected signature.

