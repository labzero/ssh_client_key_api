defmodule SSHClientKeyAPITest do
  use ExUnit.Case

  alias SSHClientKeyAPI
  alias SSHClientKeyAPI.KeyError

  @private_key """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpQIBAAKCAQEAr7CylYwuNUCYjOV7uj0X8ZRVVKlwhKtavL0vtmCiSes/TQ+u
  bQb7787djy4fILh/9ALsvOs6mzmAI9Ye6CxwG2nPhbweD76K/92cAAvbcwWFhKTS
  6q2MY6XhATcORqQmYhi6JToYkz51JFeG0k38TwyiIBaLe4yKTCnZ6F0tIB9szdR8
  pNOoZTMDAjXRDA1T0Y1wgxXn5dCFR4ywDcphRTu18FWhulruyPGQjRjFRzZCF8rO
  PYRCVBaWCIQ9Guj6VnAOaPH3tIkkdTxAeMigflCsCbFttbKLSVbi+woQrOnpQt1G
  T9YPaZed9vuXXJMI5IzUacoveyqr/X5cOfdVjwIDAQABAoIBAQCWJHRJt1WZ7s0v
  w8H8A8/dhT1zL6ZXyrStjSQkQOsQLrmXGqqexBQz+V6AyRKS/PlkR8eXH5OjKf2n
  IoqhMbDQzJkrmfs6y0SwqutxYrC02GglVlJledD7K7xhNHK/zfJ7bNRPkhmEZCDp
  4N74BOt1hr9amsmy2QUrV6zAljhFNQtGXlMIzjSwkhAO5RyVDdNUIuXVbK4vYQ8n
  60LAFUqrNMU0H5P7N1I9Wv1XdVroQ23bZkkoQ2YNg3+Xt8/ma1R8ImliODq593EF
  EWDdtcm6gUeKfZSmu3V3XLX2w03/xng9PiQJWhDyGiiqylLWw61V72BOfk8Lsq03
  bCI8HP5pAoGBANmMlI31H1E6zNrJ5/1+2IETRLJhwhCE5SJ14UgHpGjzWpCRVoi1
  KY+N6FfUgReMn6efFtJj59cKUxkODDr4yt+8mfM0evfIUJumQ56czDv5l2m3dnm1
  0JOX4jIwetFv0ROrbk7EONkg4BYLV3OFlekB+iNR0cW3mtPM/x35hvbbAoGBAM6+
  Icf5pDwvU9tqgBlbYdN9D8IJa2kTC2818XAeEBcnDsQNrpKNGfG7jcOb7Os7Qs4q
  ArIrfaWKH5OnRv8sxEJzvR1yQ7zfN0qL5+FgI95/5GmNzmiIOMIRltszuqvXhEbf
  VfxoEOrYidiliI1P2oSkaSHnKh06vTcX/Iuve3hdAoGAPLahFuUb8l2Iol7K4dIu
  tgccmvPxZw7Pq8heMO4BElEoK0SEc+6rRKcD+s8Rn/Lc87jQc7LyFu+ItWtYOnUI
  mVxXUqqIzvIWnPnP0UpNLUfA2/4ZkGoPZcFznTIudJjSLr0fMdhNTTuBjmVn6JOV
  fMvSdVz2QEm3afjCEil7YxUCgYEAkSPH4XUvyJTNQTfGUIbn6apdurIUNwMIvv1W
  z4g7cZWY9yhHy1jFwwARqSa5L/c9kjDKDb0ci2+pdWY1IIWUDrbkKF0Ekv79+Ra5
  Jm7xH44Xk8bbBmXDuvLQPnlVbrhxg7Pc0MNaRRTZyT+E2vgZh49Iw2VfGoAXQCtV
  v9blTn0CgYEAoaLnpcDDIAJrSEuYJlmMkCSOLnDaUJ2Gvk7h8J3AKUJqaZKDrYtp
  LkmEnkNn9pRguHw5O4t2A2/MPTMMPl9okxWUxmFol6vrLcVWJ7fHKnAgN4VeVdmV
  3wC+maU88MNIdY/eZWowKv/3ZzENQAJYVSOoDKRM5prZ4UMml4xIv4c=
  -----END RSA PRIVATE KEY-----
  """

  @known_hosts """
  github.com,192.30.252.128 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
  """

  @decoded_pem {
    :RSAPrivateKey,
    :"two-prime",
    22_178_836_200_351_380_318_740_579_128_076_760_436_035_138_298_677_133_998_095_994_045_880_250_237_512_489_621_454_049_374_968_347_715_235_055_783_881_967_698_436_999_743_499_552_314_220_245_159_073_073_380_722_782_484_638_674_394_343_203_468_456_842_721_969_160_490_509_408_462_854_393_345_405_217_052_033_027_002_266_498_826_680_781_860_593_217_442_724_766_608_969_408_399_340_485_759_397_900_671_701_217_164_071_787_627_996_052_566_922_654_086_785_056_460_976_416_517_428_062_469_453_531_934_201_888_286_810_352_377_976_660_566_632_576_939_435_504_625_681_508_553_755_882_812_006_916_212_863_287_750_386_635_961_610_258_614_389_401_711_948_452_227_087_543_533_788_958_800_504_728_999_838_598_664_499_003_820_759_527_927_048_804_714_300_161_960_621_149_036_100_364_182_740_694_238_727_122_433_513_404_946_091_683_042_703,
    65537,
    18_953_722_005_479_038_672_989_358_915_211_180_275_890_260_321_558_970_411_086_292_300_953_891_314_102_903_798_293_741_601_596_842_249_220_589_427_161_410_575_497_215_994_540_174_656_492_260_412_045_190_058_045_697_523_798_132_914_292_381_351_875_465_619_868_574_569_967_505_985_612_493_829_380_502_486_125_604_518_301_719_636_021_034_677_605_693_414_631_216_007_271_459_728_426_119_381_823_980_696_705_221_015_479_522_156_363_868_435_684_783_617_296_463_247_438_499_300_802_671_603_744_372_814_426_304_362_919_053_721_052_072_690_042_881_679_754_394_100_902_833_620_569_116_419_541_999_627_788_678_348_085_500_419_601_780_112_784_642_580_771_348_412_671_226_267_444_389_048_117_048_054_825_692_970_232_535_861_820_613_163_424_630_322_678_634_426_098_569_280_437_755_714_074_716_898_258_095_743_415_742_430_656_778_272_361,
    152_768_202_594_113_506_003_906_892_512_748_290_305_531_150_912_607_635_622_225_249_629_386_697_488_954_984_355_599_970_491_458_110_778_989_746_505_533_403_503_662_866_670_470_953_760_749_589_017_642_309_508_310_049_856_672_577_159_050_375_653_128_905_845_977_073_586_607_530_375_373_027_518_020_058_386_877_444_130_805_997_536_867_700_689_067_133_764_524_765_224_528_717_473_435_950_253_382_932_149_817_505_499,
    145_179_663_200_449_145_917_521_205_971_590_191_715_095_399_605_877_657_860_535_867_727_166_023_541_655_152_176_425_320_419_506_590_078_056_361_653_718_878_871_175_026_174_125_734_643_334_617_196_310_933_880_264_431_271_402_500_332_782_840_931_546_131_335_362_589_195_212_219_385_352_510_583_753_009_500_018_046_055_463_721_898_551_203_113_792_493_296_805_078_356_511_882_223_907_692_461_773_372_201_488_840_797,
    42_634_396_225_740_208_200_122_939_165_023_822_110_993_251_906_428_332_934_533_161_660_153_542_229_168_052_609_425_568_156_747_621_132_302_706_312_254_237_302_317_680_568_273_093_737_646_062_272_192_469_000_823_821_839_244_113_039_031_865_521_701_141_155_727_614_567_329_168_722_486_117_358_203_562_383_020_102_433_014_048_475_659_707_426_385_673_383_785_616_612_854_269_230_955_697_241_777_527_641_182_266_133,
    101_920_611_626_859_098_746_040_147_787_461_939_524_540_705_867_934_527_984_274_451_657_219_304_776_355_522_780_797_909_077_026_392_768_989_962_056_944_197_903_228_585_062_565_435_177_154_621_093_200_325_875_415_203_905_670_958_966_858_503_264_102_811_489_825_554_515_502_983_073_693_999_716_921_620_063_267_013_762_696_345_283_281_845_431_778_671_957_714_037_110_407_177_460_667_546_919_659_598_114_321_682_045,
    113_504_902_981_879_519_219_294_186_506_942_993_139_718_372_538_463_522_557_610_536_232_722_856_450_238_191_548_259_358_573_620_555_616_453_272_575_244_746_754_527_476_128_589_876_390_856_908_911_294_135_573_670_756_100_331_272_684_920_761_429_283_802_284_667_615_556_476_745_952_741_230_523_406_386_621_965_212_672_405_641_392_988_569_738_039_218_761_014_896_354_457_746_693_861_804_733_309_700_621_570_981_767,
    :asn1_NOVALUE
  }

  @host_key {
    :RSAPublicKey,
    21_634_204_163_197_213_132_817_109_123_906_975_906_368_888_521_544_012_567_769_262_995_559_431_966_147_970_056_259_890_368_935_740_096_079_275_379_887_017_970_430_632_559_083_119_648_736_096_672_444_000_478_892_100_121_400_122_505_155_635_695_213_610_246_722_639_150_597_148_186_404_829_574_795_017_869_184_029_845_276_838_222_700_401_896_051_725_788_665_083_080_114_314_875_103_545_837_696_279_553_436_341_967_388_240_785_773_957_395_421_170_074_137_268_759_810_304_409_727_303_757_139_265_883_118_481_355_074_238_232_002_946_450_070_460_602_471_201_997_377_623_196_017_810_991_617_729_908_588_802_783_067_540_409_316_213_603_919_494_955_068_312_762_445_623_851_275_603_318_105_356_333_614_840_694_877_780_018_045_461_415_298_887_693_169_943_421_044_958_989_561_462_337_777_142_733_008_105_081_260_079_805_978_461_159_529,
    35
  }

  @protected_key """
  -----BEGIN RSA PRIVATE KEY-----
  Proc-Type: 4,ENCRYPTED
  DEK-Info: AES-128-CBC,DFA91AAB32A89BD925F1A1F575A097AB

  p+Zit/zNJL0We7/it9LNP7Obf5QPpKbxej1/22dcyPTM0i+UNEzc0UZ1uq8E7HtL
  T4xbXIdm8oErcfHMUvFIAGWPo7tlIPhxuELdf+PqF8BkWyKY51PfzaPkLZ9DmkBt
  bhRqTdOhiSs8S2034Fut20XdK14ienBoKhRadKdT1qNMsUbIiITCLPE1RRAyivyt
  gA4iLhpJYW2Z3JxrNaTYONFWVsg7QphKLGqlfPJhJt5vi653NOAs5R/4zh0Ydraq
  wV61sL7byOjbCbUTz2MVlsL5tjSg9Yu8pXDCoHDA2x9d1BUK2nmVUCL4ex3tt1Mo
  2ZPMZ8d/wzdtF0WYzTursL2KHrnzVTKMHCj5FSwVAPDpd8866LmJpTSmO++jbGfm
  e98sfCO8NDNS/wqGiTyfvMwMNxAPHq6j92IaKaQn6wah0VfTdqxIKM8NbHS+uNWU
  jp1Q6f9YspqRS8/x6tAXYLAOxNLcbrQUVf6CfDNEw0PfXPEu8n73e/bTc5vqgrfp
  2sA+lcEIZIofabCs+MfvrE8yCD8YioNEEDg+rSwNczJy7CXLuuKjY+qrxwO8hoZ9
  aMSc408eQJkA8qf4WKrtnpA4uTfK95pt3sIPUEvaUlyos8kPzkVayAhWBK4iLDTJ
  kd/OKbSwaA1Wu6nBp7yvXXzf4PnSTFVQCVRTBp0Y7RN9F9wQdUkykDyQ0V+hfMzR
  amca+edDJv/IktYYERooDqUmTQsXrhvO7RCcCQZ4Fth49RcMnvAOkZvdvq2tBEyS
  FSlw/QlRe3XqAJDRtHyiI2d4JIPFcOjZQSF7fURYPEKaRRtQRvSaI0D9fYwuRZDY
  -----END RSA PRIVATE KEY-----
  """

  @decoded_protected_pem {
    :RSAPrivateKey,
    :"two-prime",
    132_644_066_701_965_272_197_990_416_254_098_197_235_787_282_065_089_689_218_614_762_118_634_180_485_504_252_419_171_115_297_575_357_647_736_655_424_494_954_755_823_649_751_061_913_583_651_962_116_290_698_614_376_100_307_097_340_066_550_065_146_248_139_799_167_207_333_435_447_819_433_955_059_495_419_817_121_288_882_820_925_847_183_767_685_560_609_870_341_092_035_059_556_595_536_596_844_199_276_780_741_455_007,
    65537,
    4_748_203_007_199_147_482_742_351_900_943_198_051_713_642_121_621_380_455_420_147_884_863_753_107_694_782_736_093_739_971_132_517_341_983_767_850_616_677_050_477_780_220_577_555_415_524_779_943_006_515_081_484_420_579_768_646_162_293_126_602_490_325_684_200_296_707_962_604_521_190_466_115_708_887_145_509_292_672_387_824_147_839_707_726_307_745_306_505_434_107_017_658_304_222_374_142_807_427_779_569_591_841,
    11_988_768_018_285_790_698_753_882_287_494_149_879_784_910_045_246_843_677_717_156_802_671_895_835_058_082_484_936_332_025_370_014_112_487_477_674_161_019_734_997_268_619_991_468_356_409_736_560_275_858_233,
    11_064_028_138_641_999_692_517_138_465_144_239_550_484_238_741_835_146_125_834_625_270_799_083_719_811_495_455_735_901_930_521_799_072_207_529_403_150_816_088_802_154_862_236_631_387_546_405_357_016_176_279,
    7_850_496_353_277_304_543_037_106_647_661_800_846_712_077_369_909_643_353_056_010_866_940_269_004_707_533_299_373_524_709_229_201_148_014_100_498_750_631_886_223_168_329_751_649_671_411_932_869_741_343_913,
    646_584_795_932_051_494_916_469_174_992_789_378_188_727_503_261_190_009_642_592_959_506_240_606_785_144_690_716_213_808_900_292_818_507_939_600_745_649_413_615_396_693_812_141_205_949_352_770_455_955_493,
    4_566_036_402_171_485_150_769_926_802_083_798_951_194_882_888_095_836_349_970_263_346_101_192_140_596_539_500_708_416_193_259_131_036_390_661_751_045_734_051_914_655_362_937_142_581_499_441_353_424_320_998,
    :asn1_NOVALUE
  }

  setup do
    %{
      known_hosts: File.open!(@known_hosts, [:ram, :binary, :write, :read]),
      key: File.open!(@private_key, [:ram, :binary]),
      protected_key: File.open!(@protected_key, [:ram, :binary])
    }
  end

  test "add_host_key writes an entry to known hosts if silently_accept_hosts is true", %{
    known_hosts: known_hosts
  } do
    SSHClientKeyAPI.add_host_key(
      "example.com",
      @host_key,
      key_cb_private: [
        silently_accept_hosts: true,
        known_hosts: known_hosts,
        known_hosts_data: IO.binread(known_hosts, :all)
      ]
    )

    :file.position(known_hosts, :bof)
    result = IO.binread(known_hosts, :all)
    assert result =~ "example.com"
  end

  test "add_host_key returns an error if silently_accept_hosts is false", %{
    known_hosts: known_hosts
  } do
    result =
      SSHClientKeyAPI.add_host_key(
        "example.com",
        @host_key,
        key_cb_private: [
          silently_accept_hosts: false,
          known_hosts: known_hosts,
          known_hosts_data: IO.binread(known_hosts, :all)
        ]
      )

    assert {:error, _message} = result
  end

  test "is_host_key returns true if host and key match known hosts entry", %{
    known_hosts: known_hosts
  } do
    result =
      SSHClientKeyAPI.is_host_key(
        @host_key,
        'github.com',
        :"ssh-dss",
        key_cb_private: [
          silently_accept_hosts: false,
          known_hosts: known_hosts,
          known_hosts_data: IO.binread(known_hosts, :all)
        ]
      )

    assert result
  end

  test "is_host_key returns false if host and key do not match known hosts entry", %{
    known_hosts: known_hosts
  } do
    result =
      SSHClientKeyAPI.is_host_key(
        @host_key,
        'other.com',
        :"ssh-dss",
        key_cb_private: [
          silently_accept_hosts: false,
          known_hosts: known_hosts,
          known_hosts_data: IO.binread(known_hosts, :all)
        ]
      )

    refute result
  end

  test "user key returns the contents of the key option", %{key: key} do
    result =
      SSHClientKeyAPI.user_key(
        :"ssh-dss",
        key_cb_private: [identity: key, identity_data: IO.binread(key, :all)]
      )

    assert result == {:ok, @decoded_pem}
  end

  test "user key returns error if passphrase is missing for protected key", %{
    protected_key: protected_key
  } do
    assert_raise KeyError, ~r/passphrase required/, fn ->
      SSHClientKeyAPI.user_key(
        :"ssh-dss",
        key_cb_private: [identity: protected_key, identity_data: IO.binread(protected_key, :all)]
      )
    end
  end

  test "user key returns error if passphrase is incorrect for protected key", %{
    protected_key: protected_key
  } do
    assert_raise KeyError, ~r/passphrase invalid/, fn ->
      SSHClientKeyAPI.user_key(
        :"ssh-dss",
        key_cb_private: [
          passphrase: 'wrong',
          identity: protected_key,
          identity_data: IO.binread(protected_key, :all)
        ]
      )
    end
  end

  test "user key returns error if trying to use unsupported algorithm", %{
    protected_key: protected_key
  } do
    assert_raise KeyError, ~r/not supported/, fn ->
      SSHClientKeyAPI.user_key(
        :"ssh-scooby-doo",
        key_cb_private: [
          passphrase: 'wrong',
          identity: protected_key,
          identity_data: IO.binread(protected_key, :all)
        ]
      )
    end
  end

  test "with correct passphrase, user key returns contents of protected key", %{
    protected_key: protected_key
  } do
    result =
      SSHClientKeyAPI.user_key(
        :"ssh-dss",
        key_cb_private: [
          passphrase: 'phrase',
          identity: protected_key,
          identity_data: IO.binread(protected_key, :all)
        ]
      )

    assert result == {:ok, @decoded_protected_pem}
  end

  test "with options reads the known_hosts", %{known_hosts: known_hosts, key: key} do
    {_, opts} = SSHClientKeyAPI.with_options(known_hosts: known_hosts, identity: key)
    assert Keyword.get(opts, :known_hosts_data) == @known_hosts
  end

  test "with options reads the key file", %{known_hosts: known_hosts, key: key} do
    {_, opts} = SSHClientKeyAPI.with_options(known_hosts: known_hosts, identity: key)
    assert Keyword.get(opts, :identity_data) == @private_key
  end
end
