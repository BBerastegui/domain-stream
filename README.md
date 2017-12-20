# ~~Bucket~~ Domain Stream

**Find interesting ~~Amazon S3 Buckets~~ domains by watching certificate transparency logs.**

This tool simply listens to various certificate transparency logs (via certstream) and attempts to find ~~public S3 buckets~~ domains from permutations of the certificates domain name.

This is based on the work done by https://github.com/eth0izzle/bucket-stream to monitor s3 buckets.

## Installation

Python 3.4+ and pip3 are required. Then just:

1. `git clone https://github.com/bberastegui/domain-stream.git`
2. *(optional)* Create a virtualenv with `pip3 install virtualenv && virtualenv .virtualenv && source .virtualenv/bin/activate`
2. `pip3 install -r requirements.txt`
3. `python3 domain-stream.py`

Docker instructions will come later.

## Usage

Simply run `python3 domain-stream.py`.

    usage: python domain-stream.py

    Find interesting domains by watching certificate transparency logs.

    optional arguments:
      -h, --help            Show this help message and exit
      --only-interesting    Only log 'interesting' buckets whose contents match
                            anything within keywords.txt (default: False)
      --skip-lets-encrypt   Skip certs (and thus listed domains) issued by Let's
                            Encrypt CA (default: False)
      -t , --threads        Number of threads to spawn. More threads = more power.
                            Limited to 5 threads if unauthenticated.
                            (default: 20)
      --ignore-rate-limiting
                            If you ignore rate limits not all buckets will be
                            checked (default: False)
      -l, --log             Log found buckets to a file buckets.log (default:
                            False)

## F.A.Qs

- **Nothing appears to be happening**

   Patience! Sometimes certificate transparency logs can be quiet for a few minutes. Ideally provide AWS secrets in `config.yaml` is this greatly speeds up the checking speed.

- **I found something highly confidential**

   **Report it** - please! You can usually figure out the owner from the bucket name or by doing some quick reconnaissance.

## Contributing

1. Fork it, baby!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request.

## License

MIT. See LICENSE
