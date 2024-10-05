<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('TesteAdicionar');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$EnviarCOM = (isset($_POST['EnviarCOM'])) ? htmlentities($_POST['EnviarCOM']) : '';
$obs = (isset($_POST['obs'])) ? htmlentities($_POST['obs']) : '';
$XML = (isset($_POST['XML'])) ? htmlentities($_POST['XML']) : 'N';
$EnviarEmail = (isset($_POST['EnviarEmail'])) ? htmlentities($_POST['EnviarEmail']) : 'off';
$EnviarSMS = (isset($_POST['EnviarSMS'])) ? htmlentities($_POST['EnviarSMS']) : 'off';
$EditarPorEmail = (isset($_POST['EditarPorEmail'])) ? htmlentities($_POST['EditarPorEmail']) : 'N';
$EditarPorSMS = (isset($_POST['EditarPorSMS'])) ? htmlentities($_POST['EditarPorSMS']) : 'N';
$EditarNome = (isset($_POST['EditarNome'])) ? htmlentities($_POST['EditarNome']) : '';
$EditarSobrenome = (isset($_POST['EditarSobrenome'])) ? htmlentities($_POST['EditarSobrenome']) : '';
$EditarUsuario = (isset($_POST['EditarUsuario'])) ? htmlentities($_POST['EditarUsuario']) : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? htmlentities($_POST['EditarSenha']) : '';
$EditarEmail = (isset($_POST['EditarEmail'])) ? htmlentities($_POST['EditarEmail']) : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? htmlentities($_POST['EditarCelular']) : '';
$EditarPremium = (isset($_POST['EditarPremium'])) ? htmlentities($_POST['EditarPremium']) : '';
$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
$EditarConexao = 1;
$CadUser = InfoUser(2);
$acesso = InfoUser(3);	
$VerificarEmailUser = VerificarEmailUser($CadUser, 'DadosDeAcessoTeste');
$VerificarSMSUser = VerificarSMSUser($CadUser, 'DadosDeAcessoTeste');

$VerificarCaracterUsuario = VerificarCaracter($EditarUsuario);
$VerificarCaracterSenha = VerificarCaracter($EditarSenha);

	$bloqueado = "N";
	$SQLTempo = "SELECT tempo FROM tempoteste WHERE id = :id AND bloqueado = :bloqueado";
	$SQLTempo = $painel_geral->prepare($SQLTempo);
	$SQLTempo->bindParam(':id', $EditarPremium, PDO::PARAM_STR);
	$SQLTempo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLTempo->execute();
	$LnTempo = $SQLTempo->fetch();
	
	$VerificarLimiteTeste = VerificarLimiteTeste($CadUser);
	$VerificarCotaTeste = VerificarCotaTeste($CadUser);
	$CotaTesteDisponivel = $VerificarLimiteTeste - $VerificarCotaTeste;
		
	if( ($CotaTesteDisponivel < 1) && ($VerificarLimiteTeste != 0) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['vntmldtd'], "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(substr_count($EditarUsuario, " ") > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['unpce'], "danger");
	}
	elseif (VerificarUsuarioEditar($EditarUsuario, NULL, $acesso) == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['uieeu'], "danger");
	}
	elseif(!empty($VerificarCaracterUsuario[0])){
		echo MensagemAlerta($_TRA['erro'], $_TRA['unpcec'].$VerificarCaracterUsuario[1], "danger");
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
	elseif( empty($EditarConexao) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['ceuco'], "danger");
	}
	elseif( is_numeric($EditarConexao) == false ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['codcan'], "danger");
	}
	elseif( empty($EditarPremium) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dpeuco'], "danger");
	}
	elseif( empty($LnTempo) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['ttsned'], "danger");
	}
	elseif( empty($EditarPerfil) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
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
	else{	
	
	$EditarPremium = time() + (3600 * 24 * $LnTempo['tempo']);
		
	$ArrayEditarPerfil = $EditarPerfil;
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	$DataAtual = date('Y-m-d H:i:s');
			
	$SQL = "INSERT INTO teste (
			CadUser,
			nome,
            sobrenome,
            usuario,
			senha,
			email,
			celular,
			conexao,
			perfil,
			data_cadastro,
			data_premio,
			VencEmail,
			VencSMS,
			xml,
			obs
            ) VALUES (
			:CadUser,
			:nome,
            :sobrenome,
            :usuario,
			:senha,
			:email,
			:celular,
			:conexao,
			:perfil,
			:data_cadastro,
			:data_premio,
			:VencEmail,
			:VencSMS,
			:xml,
			:obs
			)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':sobrenome', $EditarSobrenome, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $EditarUsuario, PDO::PARAM_STR); 
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR);
	$SQL->bindParam(':celular', $EditarCelular, PDO::PARAM_STR); 
	$SQL->bindParam(':conexao', $EditarConexao, PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(':data_cadastro', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR);
	$SQL->bindParam(':VencEmail', $EditarPorEmail, PDO::PARAM_STR);
	$SQL->bindParam(':VencSMS', $EditarPorSMS, PDO::PARAM_STR);
	$SQL->bindParam(':xml', $XML, PDO::PARAM_STR);
	$SQL->bindParam(':obs', $obs, PDO::PARAM_STR);
	$SQL->execute(); 
	
	$VcCli = date('d/m/Y', $EditarPremium);
	
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
	
	if( ($EnviarSMS == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, 'DadosDeAcessoTeste', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	if( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeueeus'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeueeus'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccseecsoueaeos'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeoesecs'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeue'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeus'], "success", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeoe'], "warning", "index.php?p=teste");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeos'], "warning", "index.php?p=teste");
		exit;
	}
	
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=teste");
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