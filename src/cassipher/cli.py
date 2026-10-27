"""Command-line interface. Passwords are prompted, never accepted as CLI args."""
import argparse
import getpass
import json
import sys
from pathlib import Path
from .catalog import METHODS, METHOD_BY_CODE, HISTORICAL, MODERN
from .engine import encrypt, decrypt, inspect_file, Options


def main(argv=None):
    parser = argparse.ArgumentParser(prog='cassipher', description='Offline file encryption and archive restoration.')
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encrypt', help='Encrypt one or more files/folders')
    enc.add_argument('inputs', nargs='+')
    enc.add_argument('-o', '--output', required=True)
    enc.add_argument('-m', '--method', choices=[m.code for m in METHODS if m.implemented], default='aes256')
    enc.add_argument('-c', '--compression', choices=['none','zlib','bz2','lzma','zstd','auto'],default='zlib')
    enc.add_argument('--pad-file', help='Separate OTP pad path (new, unless --existing-pad)')
    enc.add_argument('--existing-pad', action='store_true',help='Import a never-used pad of exact required length')
    dec = commands.add_parser('decrypt', help='Restore a native encrypted container')
    dec.add_argument('input')
    dec.add_argument('-o','--output-dir',required=True)
    dec.add_argument('--pad-file',help='Path to OTP keyfile')
    info=commands.add_parser('inspect',help='Print public header metadata (not authenticated until decryption)')
    info.add_argument('input')
    commands.add_parser('methods',help='List method availability')
    args=parser.parse_args(argv)
    if args.command=='methods':
        for m in METHODS:
            print(f'{m.code:12s} {m.name:28s} {"implemented" if m.implemented else "planned"}  [{m.security}]')
        return 0
    if args.command=='inspect':
        print(json.dumps(inspect_file(args.input),indent=2,ensure_ascii=False))
        return 0
    try:
        if args.command=='encrypt':
            method=METHOD_BY_CODE[args.method]
            if method.security not in ('Recommended',) and args.method != 'otp':
                print('WARNING: historical cipher is NOT secure for sensitive data.',file=sys.stderr)
            password=''
            key=''
            if args.method in MODERN:
                password=getpass.getpass('Encryption password (10+ characters): ')
                if password!=getpass.getpass('Repeat password: '):
                    raise ValueError('Passwords do not match.')
            if args.method in HISTORICAL and args.method!='atbash':
                key=getpass.getpass('Historical cipher key: ')
            if args.method=='otp' and not args.pad_file:
                raise ValueError('OTP requires --pad-file path.')
            result=encrypt(args.inputs,args.output,Options(method=args.method,compression=args.compression,
                    password=password,key=key,pad_path=args.pad_file or '',generate_pad=not args.existing_pad))
            print('Encrypted:',result['output'])
            if result['pad']:
                print('SAVE THIS SECRET PAD SEPARATELY:',result['pad'])
            return 0
        h=inspect_file(args.input)
        method=h['method']
        password=getpass.getpass('Decryption password: ') if method in MODERN else ''
        key=getpass.getpass('Historical key: ') if method in HISTORICAL and method!='atbash' else ''
        if method=='otp' and not args.pad_file:
            raise ValueError('OTP decryption requires --pad-file.')
        result=decrypt(args.input,args.output_dir,password=password,key=key,pad_path=args.pad_file or '')
        for f in result['outputs']:
            print('Restored:',f)
        return 0
    except Exception as exc:
        print(f'Error: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
