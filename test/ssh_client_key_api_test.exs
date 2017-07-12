defmodule SSHClientKeyAPITest do
  use ExUnit.Case

  alias SSHClientKeyAPI

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
    22178836200351380318740579128076760436035138298677133998095994045880250237512489621454049374968347715235055783881967698436999743499552314220245159073073380722782484638674394343203468456842721969160490509408462854393345405217052033027002266498826680781860593217442724766608969408399340485759397900671701217164071787627996052566922654086785056460976416517428062469453531934201888286810352377976660566632576939435504625681508553755882812006916212863287750386635961610258614389401711948452227087543533788958800504728999838598664499003820759527927048804714300161960621149036100364182740694238727122433513404946091683042703, 65537, 18953722005479038672989358915211180275890260321558970411086292300953891314102903798293741601596842249220589427161410575497215994540174656492260412045190058045697523798132914292381351875465619868574569967505985612493829380502486125604518301719636021034677605693414631216007271459728426119381823980696705221015479522156363868435684783617296463247438499300802671603744372814426304362919053721052072690042881679754394100902833620569116419541999627788678348085500419601780112784642580771348412671226267444389048117048054825692970232535861820613163424630322678634426098569280437755714074716898258095743415742430656778272361, 152768202594113506003906892512748290305531150912607635622225249629386697488954984355599970491458110778989746505533403503662866670470953760749589017642309508310049856672577159050375653128905845977073586607530375373027518020058386877444130805997536867700689067133764524765224528717473435950253382932149817505499, 145179663200449145917521205971590191715095399605877657860535867727166023541655152176425320419506590078056361653718878871175026174125734643334617196310933880264431271402500332782840931546131335362589195212219385352510583753009500018046055463721898551203113792493296805078356511882223907692461773372201488840797, 42634396225740208200122939165023822110993251906428332934533161660153542229168052609425568156747621132302706312254237302317680568273093737646062272192469000823821839244113039031865521701141155727614567329168722486117358203562383020102433014048475659707426385673383785616612854269230955697241777527641182266133, 101920611626859098746040147787461939524540705867934527984274451657219304776355522780797909077026392768989962056944197903228585062565435177154621093200325875415203905670958966858503264102811489825554515502983073693999716921620063267013762696345283281845431778671957714037110407177460667546919659598114321682045, 113504902981879519219294186506942993139718372538463522557610536232722856450238191548259358573620555616453272575244746754527476128589876390856908911294135573670756100331272684920761429283802284667615556476745952741230523406386621965212672405641392988569738039218761014896354457746693861804733309700621570981767,
    :asn1_NOVALUE
  }

  @host_key {
    :RSAPublicKey,
    21634204163197213132817109123906975906368888521544012567769262995559431966147970056259890368935740096079275379887017970430632559083119648736096672444000478892100121400122505155635695213610246722639150597148186404829574795017869184029845276838222700401896051725788665083080114314875103545837696279553436341967388240785773957395421170074137268759810304409727303757139265883118481355074238232002946450070460602471201997377623196017810991617729908588802783067540409316213603919494955068312762445623851275603318105356333614840694877780018045461415298887693169943421044958989561462337777142733008105081260079805978461159529,
    35
  }

  setup do
    %{
      known_hosts: File.open!(@known_hosts, [:ram, :binary, :write, :read]),
      key: File.open!(@private_key, [:ram, :binary])
    }
  end

  test "add_host_key writes an entry to known hosts if accept_hosts is true", %{known_hosts: known_hosts} do
    SSHClientKeyAPI.add_host_key(
      "example.com",
      @host_key,
      [key_cb_private: [accept_hosts: true, known_hosts: known_hosts, known_hosts_data: IO.binread(known_hosts, :all)]]
      )
    :file.position(known_hosts, :bof)
    result = IO.binread(known_hosts, :all)
    assert result =~ "example.com"
  end

  test "add_host_key returns an error if accept_hosts is false", %{known_hosts: known_hosts} do
    result = SSHClientKeyAPI.add_host_key(
      "example.com",
      @host_key,
      [key_cb_private: [accept_hosts: false, known_hosts: known_hosts, known_hosts_data: IO.binread(known_hosts, :all)]])
    assert {:error, _message} = result
  end

  test "is_host_key returns true if host and key match known hosts entry", %{known_hosts: known_hosts} do
    result = SSHClientKeyAPI.is_host_key(
      @host_key,
      'github.com',
      :"ssh-dsa",
      [key_cb_private: [accept_hosts: false, known_hosts: known_hosts, known_hosts_data: IO.binread(known_hosts, :all)]])
    assert result
  end

  test "is_host_key returns false if host and key do not match known hosts entry", %{known_hosts: known_hosts} do
    result = SSHClientKeyAPI.is_host_key(
      @host_key,
      'other.com',
      :"ssh-dsa",
      [key_cb_private: [accept_hosts: false, known_hosts: known_hosts, known_hosts_data: IO.binread(known_hosts, :all)]])
    refute result
  end

  test "user key returns the contents of the key option", %{key: key} do
    result = SSHClientKeyAPI.user_key(
      :"ssh-dsa",
      [key_cb_private: [identity: key, identity_data: IO.binread(key, :all)]]
    )
    assert result == {:ok, @decoded_pem}
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