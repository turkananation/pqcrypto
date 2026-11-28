import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// NIST SP 800-185 TupleHash and TupleHashXOF samples.
///
/// Hex is inlined so this file runs on Chrome.
void main() {
  Uint8List hex(String value) {
    return Uint8List.fromList(<int>[
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16),
    ]);
  }

  Uint8List ascii(String value) => Uint8List.fromList(value.codeUnits);

  Uint8List digest(_Sample sample) {
    final elements = <Uint8List>[
      for (final item in sample.tuplesHex) hex(item),
    ];
    final customization = sample.customization.isEmpty
        ? null
        : ascii(sample.customization);
    final outputLength = sample.outputBitLength ~/ 8;
    return switch ((sample.xof, sample.securityBits)) {
      (false, 128) => TupleHash128.hash(
        elements,
        outputLength: outputLength,
        customization: customization,
      ),
      (false, 256) => TupleHash256.hash(
        elements,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 128) => TupleHashXof128.hash(
        elements,
        outputLength: outputLength,
        customization: customization,
      ),
      (true, 256) => TupleHashXof256.hash(
        elements,
        outputLength: outputLength,
        customization: customization,
      ),
      _ => throw ArgumentError.value(sample.securityBits, 'securityBits'),
    };
  }

  const samples = <_Sample>[
    _Sample(
      xof: false,
      number: 1,
      securityBits: 128,
      outputBitLength: 256,
      customization: '',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          'c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 2,
      securityBits: 128,
      outputBitLength: 256,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 3,
      securityBits: 128,
      outputBitLength: 256,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415', '202122232425262728'],
      encodedTuplesHex: <String>[
        '0118000102',
        '0130101112131415',
        '0148202122232425262728',
      ],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          'e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84',
      rateBytes: 168,
    ),
    _Sample(
      xof: false,
      number: 4,
      securityBits: 256,
      outputBitLength: 512,
      customization: '',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          'cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 5,
      securityBits: 256,
      outputBitLength: 512,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e',
      rateBytes: 136,
    ),
    _Sample(
      xof: false,
      number: 6,
      securityBits: 256,
      outputBitLength: 512,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415', '202122232425262728'],
      encodedTuplesHex: <String>[
        '0118000102',
        '0130101112131415',
        '0148202122232425262728',
      ],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 1,
      securityBits: 128,
      outputBitLength: 256,
      customization: '',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 2,
      securityBits: 128,
      outputBitLength: 256,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '3fc8ad69453128292859a18b6c67d7ad85f01b32815e22ce839c49ec374e9b9a',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 3,
      securityBits: 128,
      outputBitLength: 256,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415', '202122232425262728'],
      encodedTuplesHex: <String>[
        '0118000102',
        '0130101112131415',
        '0148202122232425262728',
      ],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8',
      rateBytes: 168,
    ),
    _Sample(
      xof: true,
      number: 4,
      securityBits: 256,
      outputBitLength: 512,
      customization: '',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '03ded4610ed6450a1e3f8bc44951d14fbc384ab0efe57b000df6b6df5aae7cd568e77377daf13f37ec75cf5fc598b6841d51dd207c991cd45d210ba60ac52eb9',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 5,
      securityBits: 256,
      outputBitLength: 512,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415'],
      encodedTuplesHex: <String>['0118000102', '0130101112131415'],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '6483cb3c9952eb20e830af4785851fc597ee3bf93bb7602c0ef6a65d741aeca7e63c3b128981aa05c6d27438c79d2754bb1b7191f125d6620fca12ce658b2442',
      rateBytes: 136,
    ),
    _Sample(
      xof: true,
      number: 6,
      securityBits: 256,
      outputBitLength: 512,
      customization: 'My Tuple App',
      tuplesHex: <String>['000102', '101112131415', '202122232425262728'],
      encodedTuplesHex: <String>[
        '0118000102',
        '0130101112131415',
        '0148202122232425262728',
      ],
      encodedNameHex: '01485475706c6548617368',
      outputHex:
          '0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a2446284dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897',
      rateBytes: 136,
    ),
  ];

  test('covers the twelve NIST TupleHash and TupleHashXOF samples', () {
    expect(samples, hasLength(12));
  });

  for (final sample in samples) {
    final label = sample.xof ? 'TupleHashXOF' : 'TupleHash';
    test('$label sample ${sample.number} at ${sample.securityBits} bits', () {
      expect(sample.outputBitLength % 8, 0);
      expect(sample.tuplesHex, hasLength(sample.encodedTuplesHex.length));
      expect(
        sample.rateBytes,
        sample.securityBits == 128
            ? Fips202Parameters.shake128.rateBytes
            : Fips202Parameters.shake256.rateBytes,
      );
      expect(encodeString(ascii('TupleHash')), hex(sample.encodedNameHex));
      for (var i = 0; i < sample.tuplesHex.length; i++) {
        expect(
          encodeString(hex(sample.tuplesHex[i])),
          hex(sample.encodedTuplesHex[i]),
        );
      }
      final lengthBits = sample.xof ? 0 : sample.outputBitLength;
      expect(rightEncode(lengthBits).isNotEmpty, isTrue);
      if (sample.xof) {
        expect(rightEncode(0), hex('0001'));
      } else {
        expect(rightEncode(sample.outputBitLength), isNot(hex('0001')));
      }

      final elements = <Uint8List>[
        for (final item in sample.tuplesHex) hex(item),
      ];
      final copies = <Uint8List>[
        for (final element in elements) Uint8List.fromList(element),
      ];
      expect(digest(sample), hex(sample.outputHex));
      expect(elements, copies);
    });
  }

  test('tuple boundaries and empty elements change the digest', () {
    final a = ascii('a');
    final b = ascii('b');
    final c = ascii('c');
    final ab = ascii('ab');
    final bc = ascii('bc');
    final empty = Uint8List(0);
    expect(
      TupleHash128.hash([ab, c], outputLength: 32),
      isNot(TupleHash128.hash([a, bc], outputLength: 32)),
    );
    expect(
      TupleHash256.hash([ab, c], outputLength: 64),
      isNot(TupleHash256.hash([a, bc], outputLength: 64)),
    );
    expect(
      TupleHash128.hash([a, empty, b], outputLength: 32),
      isNot(TupleHash128.hash([a, b], outputLength: 32)),
    );
    expect(
      TupleHashXof128.hash([a, empty, b], outputLength: 32),
      isNot(TupleHashXof128.hash([a, b], outputLength: 32)),
    );
  });

  test('fixed-output TupleHash and TupleHashXOF differ', () {
    final elements = <Uint8List>[hex('000102'), hex('101112131415')];
    final customization = ascii('My Tuple App');
    expect(
      TupleHash128.hash(
        elements,
        outputLength: 32,
        customization: customization,
      ),
      isNot(
        TupleHashXof128.hash(
          elements,
          outputLength: 32,
          customization: customization,
        ),
      ),
    );
    expect(
      TupleHash256.hash(
        elements,
        outputLength: 64,
        customization: customization,
      ),
      isNot(
        TupleHashXof256.hash(
          elements,
          outputLength: 64,
          customization: customization,
        ),
      ),
    );
  });

  test('an empty tuple is defined and does not mutate elements', () {
    final empty = Uint8List(0);
    final elements = <Uint8List>[empty];
    expect(TupleHash128.hash(elements, outputLength: 32), hasLength(32));
    expect(elements.single, isEmpty);
    expect(TupleHash128.hash(<Uint8List>[], outputLength: 32), hasLength(32));
    expect(
      TupleHash128.hash(<Uint8List>[], outputLength: 32),
      TupleHash128.hash(
        <Uint8List>[],
        outputLength: 32,
        customization: Uint8List(0),
      ),
    );
  });

  test('a negative output length throws and names outputLength', () {
    expect(
      () => TupleHash128.hash(<Uint8List>[ascii('a')], outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
    expect(
      () => TupleHashXof256.hash(<Uint8List>[], outputLength: -1),
      throwsA(
        isA<RangeError>().having((error) => error.name, 'name', 'outputLength'),
      ),
    );
    expect(TupleHash128.hash(<Uint8List>[], outputLength: 0), isEmpty);
  });
}

class _Sample {
  const _Sample({
    required this.xof,
    required this.number,
    required this.securityBits,
    required this.outputBitLength,
    required this.customization,
    required this.tuplesHex,
    required this.encodedTuplesHex,
    required this.encodedNameHex,
    required this.outputHex,
    required this.rateBytes,
  });

  final bool xof;
  final int number;
  final int securityBits;
  final int outputBitLength;
  final String customization;
  final List<String> tuplesHex;
  final List<String> encodedTuplesHex;
  final String encodedNameHex;
  final String outputHex;
  final int rateBytes;
}
