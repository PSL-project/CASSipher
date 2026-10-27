import os
import tempfile
import unittest
from pathlib import Path

from cassipher.engine import encrypt, decrypt, inspect_file, Options
from cassipher import historical, archive

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.dest = self.root / 'restore'
        self.dest.mkdir()
        self.test_bytes = bytes(range(256))*129 + os.urandom(113)
        (self.source / 'test 🔒.bin').write_bytes(self.test_bytes)
        (self.source / 'empty.txt').write_bytes(b'')

    def check_roundtrip(self, method, compression='zlib', key='', password='correct horse battery staple'):
        options = Options(method=method, compression=compression, key=key, password=password)
        filepath = self.root / (method + '_' + compression + '.cwbox')
        result = encrypt([self.source / 'test 🔒.bin'], filepath, options)
        self.assertGreater(result['output_bytes'], 0)
        h = inspect_file(filepath)
        self.assertEqual(h['method'], method)
        restored = decrypt(filepath, self.dest, password=password, key=key)
        self.assertEqual(Path(restored['outputs'][0]).read_bytes(), self.test_bytes)
        return filepath

    def test_modern_all_compression(self):
        for cipher in ('aes256', 'aes128', 'chacha'):
            for comp in ('none','zlib','bz2','lzma'):
                with self.subTest(cipher=cipher, comp=comp):
                    self.check_roundtrip(cipher, comp)

    def test_historical(self):
        for method,key in [('caesar','119'),('atbash',''),('vigenere','my key 🔑'),('affine','5,8'),('railfence','4')]:
            with self.subTest(method=method):
                self.check_roundtrip(method, key=key)

    def test_wrong_password_corrupt_and_truncate(self):
        file = self.check_roundtrip('aes256')
        with self.assertRaises(Exception):
            decrypt(file, self.root / 'wrong', password='a wrong but sufficiently long password')
        original = file.read_bytes()
        for label,data in [('damaged', original[:200]+bytes([original[200]^3])+original[201:]), ('truncate',original[:-7]), ('append',original+b'X')]:
            bad = self.root / (label+'.cwbox')
            bad.write_bytes(data)
            with self.subTest(label=label), self.assertRaises(Exception):
                decrypt(bad, self.root / ('bad'+label), password='correct horse battery staple')

    def test_multi_file_folder_and_no_overwrite(self):
        sub = self.source / 'folder'
        sub.mkdir()
        (sub/'inside.txt').write_text('HELLO')
        p = self.root/'many.cwbox'
        encrypt([self.source/'test 🔒.bin', self.source/'empty.txt', sub], p, Options(password='correct horse battery staple'))
        with self.assertRaises(FileExistsError):
            encrypt([self.source/'empty.txt'], p, Options(password='correct horse battery staple'))
        out = decrypt(p, self.dest, password='correct horse battery staple')
        folder = Path(out['outputs'][0])
        self.assertEqual((folder/'folder'/'inside.txt').read_text(), 'HELLO')
        self.assertEqual((folder/'empty.txt').read_bytes(), b'')
        self.assertEqual((folder/'test 🔒.bin').read_bytes(), self.test_bytes)

    def test_otp_generation_roundtrip_reuse_rejected(self):
        otp_file = self.root/'test_otp.cwbox'
        pad = self.root/'test_otp.key'
        opts = Options(method='otp', compression='zlib', pad_path=str(pad), generate_pad=True)
        encrypt([self.source/'test 🔒.bin'], otp_file, opts)
        self.assertEqual(pad.stat().st_size, inspect_file(otp_file)['pad_bytes'])
        self.assertEqual(Path(decrypt(otp_file, self.dest, pad_path=pad)['outputs'][0]).read_bytes(), self.test_bytes)
        with self.assertRaises(ValueError):
            encrypt([self.source/'test 🔒.bin'], self.root/'reused.cwbox', Options(method='otp',compression='zlib',pad_path=str(pad),generate_pad=False))
        with self.assertRaises(Exception):
            decrypt(otp_file, self.dest, pad_path=self.source/'empty.txt')

    def test_archive_traversal_and_collision_blocked(self):
        import zipfile
        for entry in ('../escape','C:/secret','CON.txt','dir\\bad','dir/../evil'):
            file = self.root/'evil.zip'
            with zipfile.ZipFile(file,'w',compression=zipfile.ZIP_STORED) as zipf:
                zipf.writestr(entry, b'X')
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                archive.inspect_archive(file)

    def test_historical_rail_and_chunk_offset(self):
        data = bytes(range(256))*6
        for method,key in [('caesar','12'),('vigenere','KEY'),('atbash',''),('affine','11,2'),('railfence','5')]:
            c = historical.transform(data, method, key, False)
            self.assertEqual(historical.transform(c, method, key, True), data)

if __name__ == '__main__':
    unittest.main()

class EdgeCases(unittest.TestCase):
    def test_multichunk_and_output_inside_input_folder(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            input_folder=root/'photos'
            input_folder.mkdir()
            original=os.urandom(900_000)
            (input_folder/'sample.bin').write_bytes(original)
            encrypted=input_folder/'output.cwbox'
            encrypt([input_folder],encrypted,Options(password='this is a strong example password',compression='none'))
            restore=root/'restored'
            result=decrypt(encrypted,restore,password='this is a strong example password')
            self.assertEqual((Path(result['outputs'][0])/'photos'/'sample.bin').read_bytes(),original)
            # The temp package must not contain its own in-progress output.
            self.assertFalse((Path(result['outputs'][0])/'photos'/'output.cwbox').exists())

    def test_empty_input_and_cancellation(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'empty';p.write_bytes(b'')
            for method in ('aes256','caesar','otp'):
                outfile=d/(method+'.cwbox')
                opts=Options(method=method,password='a sufficiently strong password',key='2',compression='zlib',
                             pad_path=str(d/'pad.otpkey'),generate_pad=True)
                encrypt([p],outfile,opts)
                restored=decrypt(outfile,d/'restore',password=opts.password,key=opts.key,pad_path=opts.pad_path)
                self.assertEqual(Path(restored['outputs'][0]).read_bytes(),b'')
            cancelled_file=d/'cancel.cwbox'
            with self.assertRaises(InterruptedError):
                encrypt([p],cancelled_file,Options(password='a sufficiently strong password'),cancelled=lambda: True)
            self.assertFalse(cancelled_file.exists())

    def test_header_tamper_and_input_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'file.bin';p.write_bytes(os.urandom(800))
            outfile=d/'file.bin.cwbox';pw='a sufficiently strong password'
            encrypt([p],outfile,Options(password=pw))
            original=outfile.read_bytes()
            # corrupt an authenticated header field while preserving JSON syntax
            idx=original.find(b'"aes256"')
            self.assertGreater(idx,0)
            altered=original[:idx]+b'"aes128"'+original[idx+8:]
            outfile.write_bytes(altered)
            with self.assertRaises(Exception):
                decrypt(outfile,d/'out',password=pw)
            self.assertFalse((d/'out'/'file.bin').exists())
            self.assertEqual(p.stat().st_size,800)

class AutoCompression(unittest.TestCase):
    def test_auto_selects_valid_codec(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);src=d/'repeated.txt';src.write_bytes(b'banana'*300_000)
            out=d/'archive.cwbox';pw='some strong unique long password'
            encrypt([src],out,Options(method='aes256',password=pw,compression='auto'))
            self.assertIn(inspect_file(out)['compression'], ('none','zlib','lzma','bz2','zstd'))
            result=decrypt(out,d/'extracted',password=pw)
            self.assertEqual(Path(result['outputs'][0]).read_bytes(),src.read_bytes())

class CompressionLarge(unittest.TestCase):
    def test_compress_decompress_large_repetitive_and_random(self):
        from cassipher.compression import compress_file, decompress_file
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            samples=[b'ABCDEF'*1_000_000,os.urandom(750_000)]
            for index,data in enumerate(samples):
                source=d/f'input{index}.bin';source.write_bytes(data)
                for method in ('zlib','bz2','lzma','none'):
                    with self.subTest(sample=index,codec=method):
                        packed=d/'packed.bin';output=d/'restored.bin'
                        compress_file(source,packed,method)
                        decompress_file(packed,output,method,len(data))
                        self.assertEqual(output.read_bytes(),data)
