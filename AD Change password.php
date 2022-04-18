<?php
error_reporting(0);
ini_set(“display_errors”, 0 );

$message = array();
$message_css = "";

function changePassword($user,$oldPassword,$newPassword,$newPasswordCnf){
  global $message;
  global $message_css;

  putenv('LDAPTLS_REQCERT=allow');
  $ldap_url = "ldaps://";
  $ldap = ldap_connect($ldap_url);
  ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
  ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

  if(!substr($user,0,strrpos($user,'@'))){
    $user = $user;
  }
    else{
      $user = substr($user,0,strrpos($user,'@'));
    }

  if (ldap_bind($ldap, $user.'@hsan.com.br', $oldPassword) === false) {
    $message[] = "Erro - Seu usuário ou senha atual estão incorretos!!!";
    return false;
  }

  $ldap_binddn = "CN=administrador,CN=Users,DC=,DC=,DC=";
  $ldap_bindpw = "admin password";
  $bind = ldap_bind($ldap, $ldap_binddn, $ldap_bindpw);
  $ldap_base = "OU=Hospital_Santo_Antonio,DC=hsan,DC=com,DC=br";
  $ldap_login_attribute = "sAMAccountName";
  $ldap_fullname_attribute = "cn";
  $ldap_filter = "(&(objectClass=user)($ldap_login_attribute={$user}))";
  // bind anon and find user by uid
  $user_search = ldap_search($ldap,$ldap_base,$ldap_filter);
  $user_get = ldap_get_entries($ldap, $user_search);
  $user_entry = ldap_first_entry($ldap, $user_search);
  $user_dn = ldap_get_dn($ldap, $user_entry);
  $user_id = $user_get[0]["samaccountname"][0];
  $user_givenName = $user_get[0]["givenname"][0];
  $user_lock = $user_get[0]["useraccountcontrol"][0];//512 habilitado 514 desabilitado
  $user_search_arry = array( "*", "ou", "uid", "mail", "passwordRetryCount", "passwordhistory" );
  $user_search_filter = "(|(samaccountname=$user_id))";
  $user_search_opt = ldap_search($ldap,$user_dn,$user_search_filter,$user_search_arry);
  $user_get_opt = ldap_get_entries($ldap, $user_search_opt);
  /* Start the testing */
  $depurar = 'N';
  $depurar_array = 'N';
  if ($depurar == 'S') {
    echo  'DEPURAÇÃO <br>';
    echo  'USUÁRIO DIGITADO: ' . $user . '<br>';
    echo  'BIND: ' . $bind . '<br>';
    echo  'FILTER: ' . $ldap_filter . '<br>';
    echo  'USER SEARCH: ' . $user_search . '<br>';
    echo  'USER ENTRY: ' . $user_entry . '<br>';
    echo  'USER DN: ' . $user_dn . '<br>';
    echo  'USER ID: ' . $user_id . '<br>';
    echo  'USER NAME: ' . $user_givenName . '<br>';
    echo  'USER LOCK: ' . $user_lock . '  - 512 habilitado 514 desabilitado <br>';
    echo  'USER SEARCH FILTER: ' . $user_search_filter . '<br>';
    echo  'USER SEARCH OPT: ' . $user_search_opt . '<br>';
    if ($depurar_array == 'S') {
        echo  'ARRAY user_get<br>';
        echo  '<pre>';
        print_r($user_get);
        echo  '</pre>';
        echo  'ARRAY - user_search_arry<br>';
        echo "<pre>";
        print_r($user_search_arry);
        echo "</pre>";
    }
  }
  if ( $user_lock == 514 ) {
    $message[] = "Erro - Sua conta está bloqueada !!!";
    return false;
  }
  if ($newPassword != $newPasswordCnf ) {
    $message[] = "Erro - Sua nova senha e confirmação de nova senha não são iguais !!!";
    return false;
  }
  $ctrl1 = array(
      // LDAP_SERVER_POLICY_HINTS_OID for Windows 2012 and above
      "oid" => "1.2.840.113556.1.4.2239",
      "value" => sprintf("%c%c%c%c%c", 48, 3, 2, 1, 1));
  if (!ldap_set_option($ldap, LDAP_OPT_SERVER_CONTROLS, array($ctrl1))) {
      $message[] = "Erro - Falha ao ativar os controles do servidor !!!";
      return false;
  }
  if (strlen($newPassword) < 8 ) {
    $message[] = "Erro - Sua nova senha é muito curta.<br/>sua nova senha deve ter no mínimo 8 caracteres ou mais !!!";
    return false;
  }
  if(      (!preg_match("/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$/" ,$newPassword))
        && (!preg_match("/^(?=.*\W)(?=.*[a-z])(?=.*[A-Z]).*$/",$newPassword))
        && (!preg_match("/^(?=.*\d)(?=.*\W)(?=.*[A-Z]).*$/",$newPassword))
        && (!preg_match("/^(?=.*\d)(?=.*[a-z])(?=.*\W).*$/",$newPassword))
    ) {
    $message[] = "Erro - Sua senha deve conter uma letra maiúscula, uma letra minúscula e um número ou caracter especial !!!";
    return false;
  }
  if (!$user_get) {
    $message[] = "Erro - Impossível se conectar ao servidor, sua senha não será alterada agora !!!";
    return false;
  }
  $newPassword = "\"" . $newPassword . "\"";
  $len = strlen($newPassword);
  $newPassw = "";
  for($i=0;$i<$len;$i++) { $newPassw .= "{$newPassword{$i}}\000"; } $info["unicodepwd"] = $newPassw;
  $entry = ldap_first_entry($ldap, $user_search);
  if (!is_resource($entry)){
    exit('Couldn\'t get entry'); }
    $userDn = ldap_get_dn($ldap, $entry);
    $resultado = ldap_modify($ldap, $userDn, $info);
    if($resultado == 1) {
        $message_css = "yes";
        $message[] = "<b>" . $user_givenName . "</b> sua senha foi alterada com sucesso! Obrigado."; }
    else if (ldap_error($ldap) == 'Server is unwilling to perform') {
              $message[] = 'Sua nova senha corresponde a uma das 5 últimas senhas usadas, você DEVE criar uma nova senha';
            }
              else {$message[] = ldap_error($ldap);}
}
?>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="pt" lang="br">
<head>
<title>Alteração senha HSAN</title>
<style type="text/css">
body { font-family: Verdana; font-size: 12; }
th { font-family: Verdana; font-size: 12; text-align: right; padding: 8; }
#container { text-align: center; width: 550px; margin: 5% auto; }
.msg_yes { margin: 0 auto; text-align: center; color: green; background: #D4EAD4; border: 1px solid green; border-radius: 10px; margin: 2px; }
.msg_no { margin: 0 auto; text-align: center; color: red; background: #FFF0F0; border: 1px solid red; border-radius: 10px; margin: 2px; }
</style>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
</head>
<body>
<div id="container">
<h2>Alteração senha</h2>
<p>Sua nova senha deve conter 8 caracteres ou mais e ter pelo menos:<br/>
uma letra <b>MAIÚSCULA</b>, uma letra <b>minúscula</b> e um <b>número</b> ou <b>caracter especial</b>.<br/>
Sua nova senha não pode ser uma das 5 últimas utilizadas.</p>
<?php
      if (isset($_POST["submitted"])) {
        changePassword($_POST['username'],$_POST['oldPassword'],$_POST['newPassword1'],$_POST['newPassword2']);
        global $message_css;
        if ($message_css == "yes") {
          ?><div class="msg_yes"><?php
         } else {
          ?><div class="msg_no"><?php
          $message[] = "Sua senha não foi alterada.";
        }
        foreach ( $message as $one ) { echo "<p>$one</p>"; }
      ?></div><?php
      } ?>
<form action="<?php print $_SERVER['PHP_SELF']; ?>" name="passwordChange" method="post">
<table style="width: 400px; margin: 0 auto;">
<tr><th>Usuário:</th><td><input name="username" type="text" size="20px" autocomplete="off" /></td></tr>
<tr><th>Senha Atual:</th><td><input name="oldPassword" size="20px" type="password" /></td></tr>
<tr><th>Nova Senha:</th><td><input name="newPassword1" size="20px" type="password" /></td></tr>
<tr><th>Confirme Nova Senha:</th><td><input name="newPassword2" size="20px" type="password" /></td></tr>
<tr><td colspan="2" style="text-align: center;" >
<input name="submitted" type="submit" value="Mudar senha"/>
<button onclick="$('frm').action='changepassword.php';$('frm').submit();">Cancelar</button>
</td></tr>
</table>
</form>
</div>
</body>
</html>
