<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('TesteEditar');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$EnviarCOM = (isset($_POST['EnviarCOM'])) ? $_POST['EnviarCOM'] : '';
$obs = (isset($_POST['obs'])) ? $_POST['obs'] : '';
$EnviarEmailRen = (isset($_POST['EnviarEmailRen'])) ? $_POST['EnviarEmailRen'] : 'off';
$EnviarSMSRen = (isset($_POST['EnviarSMSRen'])) ? $_POST['EnviarSMSRen'] : 'off';
$XML = (isset($_POST['XML'])) ? $_POST['XML'] : 'N';
$IDUsuario = (isset($_POST['IDUsuario'])) ? $_POST['IDUsuario'] : '';
$Usuario = (isset($_POST['Usuario'])) ? $_POST['Usuario'] : '';
$EnviarEmail = (isset($_POST['EnviarEmail'])) ? $_POST['EnviarEmail'] : 'off';
$EnviarSMS = (isset($_POST['EnviarSMS'])) ? $_POST['EnviarSMS'] : 'off';
$EditarPorEmail = (isset($_POST['EditarPorEmail'])) ? $_POST['EditarPorEmail'] : 'N';
$EditarPorSMS = (isset($_POST['EditarPorSMS'])) ? $_POST['EditarPorSMS'] : 'N';
$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
$EditarSobrenome = (isset($_POST['EditarSobrenome'])) ? $_POST['EditarSobrenome'] : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
$EditarEmail = (isset($_POST['EditarEmail'])) ? $_POST['EditarEmail'] : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? $_POST['EditarCelular'] : '';
$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
$CadUser = InfoUser(2);
$acesso = InfoUser(3);	
$VerificarEmailUser = VerificarEmailUser($CadUser, 'DadosDeAcessoTeste');
$VerificarSMSUser = VerificarSMSUser($CadUser, 'DadosDeAcessoTeste');
$VerificarEmailUserRen = VerificarEmailUser($CadUser, 'Renovacao');
$VerificarSMSUserRen = VerificarSMSUser($CadUser, 'Renovacao');

$VerificarCaracterSenha = VerificarCaracter($EditarSenha);

	$ArvoreAdminOnline = ArvoreAdminRev($CadUser);
	$ArvoreAdminOnline[] = $CadUser;
	
	$SQLUser = "SELECT CadUser, data_premio FROM teste WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $Usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	if(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$Usuario,$_TRA['npounpav']), "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarSenha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	elseif(substr_count($EditarSenha, " ") > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['snpce'], "danger");
	}
	elseif(!empty($VerificarCaracterSenha[0])){
		echo MensagemAlerta($_TRA['erro'], $_TRA['snpcec'].$VerificarCaracterSenha[1], "danger");
	}
	elseif( !empty($EditarEmail) && substr_count($EditarEmail, "@") == 0 || !empty($EditarEmail) && substr_count($EditarEmail, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif( !empty($EditarCelular) && (is_numeric(LimparCelular($EditarCelular)) == false) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	elseif( empty($EditarPerfil) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailRen == "on") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['psautsedoernpodamt'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSRen == "on") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['psautsedoernpodamtsms'], "danger");
	}
	elseif( ($EnviarEmail == "on") && empty($EditarEmail) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 1) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cueeeacq'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 2) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeaesb'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 3) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['nenmdea'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 4) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dapdmdepd'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 5) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omanemdnapme'], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 6) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omaebrode'], "danger");
	}
	elseif( ($EnviarSMS == "on") && empty($EditarCelular) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cuco'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 1) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cucdsesa'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 2) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['acsaesbrode'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 3) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['nenmdsapasm'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 4) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dapdmdspdsm'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 5) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omanemdnapdmdspd'], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 6) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omadsebrodesm'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && empty($EditarEmail) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 1) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cueeeacq'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 2) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeaesb'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 3) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['nenmdea'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 4) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dapdmdepd'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 5) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omanemdnapme'], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 6) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omaebrode'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && empty($EditarCelular) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cuco'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 1) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cucdsesa'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 2) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['acsaesbrode'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 3) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['nenmdsapasm'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 4) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dapdmdspdsm'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 5) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omanemdnapdmdspd'], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 6) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['omadsebrodesm'], "danger");
	}
	else{		
		
	$ArrayEditarPerfil = $EditarPerfil;
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	
	$SQL = "UPDATE teste SET
				nome = :nome,
				sobrenome = :sobrenome,
				senha = :senha,
				email = :email,
				celular = :celular,
				perfil = :perfil,
				VencEmail = :VencEmail,
				VencSMS = :VencSMS,
				xml = :xml,
				obs = :obs
        	WHERE id = :id";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':sobrenome', $EditarSobrenome, PDO::PARAM_STR); 
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR);
	$SQL->bindParam(':celular', $EditarCelular, PDO::PARAM_STR); 
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(':VencEmail', $EditarPorEmail, PDO::PARAM_STR);
	$SQL->bindParam(':VencSMS', $EditarPorSMS, PDO::PARAM_STR);
	$SQL->bindParam(':xml', $XML, PDO::PARAM_STR);
	$SQL->bindParam(':obs', $obs, PDO::PARAM_STR);
	$SQL->bindParam(':id', $IDUsuario, PDO::PARAM_STR);
	$SQL->execute(); 
	
	$SQLLogin = "SELECT usuario FROM teste WHERE id = :id";
	$SQLLogin = $painel_user->prepare($SQLLogin);
	$SQLLogin->bindParam(':id', $IDUsuario, PDO::PARAM_STR);
	$SQLLogin->execute();
	$LnLogin = $SQLLogin->fetch();
	$EditarUsuario = $LnLogin['usuario'];
	
	$VcCli = date('d/m/Y', $LnUser['data_premio']);
	
	//E-mail Dados
	if( ($EnviarEmail == "on") && !empty($EditarEmail)){
		$SelecionarModelo = SelecionarModelo($CadUser, 'DadosDeAcessoTeste', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		
		$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
		$SQLUser = $painel_geral->prepare($SQLUser);
		$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQLUser->bindParam(':id', $EnviarCOM, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $EditarEmail, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	//E-mail Renovação
	if( ($EnviarEmailRen == "on") && !empty($EditarEmail)){
		$SelecionarModelo = SelecionarModelo($CadUser, 'Renovacao', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		
		$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
		$SQLUser = $painel_geral->prepare($SQLUser);
		$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQLUser->bindParam(':id', $EnviarCOM, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $EditarEmail, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	//SMS Dados
	if( ($EnviarSMS == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, 'DadosDeAcessoTeste', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	//SMS Renovação
	if( ($EnviarSMSRen == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, 'Renovacao', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	if( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsfeueeus'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsoueaeueeus'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcseecsoueaeos'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsoueaeoesecs'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsfeue'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsfeus'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsoueaeoe'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcsoueaeos'], "warning", "index.php?p=teste");
		exit;
	}
	
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=teste");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>