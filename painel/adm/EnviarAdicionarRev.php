<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevAdicionar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$EditarLimiteTeste = (isset($_POST['EditarLimiteTeste'])) ? $_POST['EditarLimiteTeste'] : '';
$obs = (isset($_POST['obs'])) ? $_POST['obs'] : '';
$EnviarEmail = (isset($_POST['EnviarEmail'])) ? $_POST['EnviarEmail'] : 'off';
$EnviarSMS = (isset($_POST['EnviarSMS'])) ? $_POST['EnviarSMS'] : 'off';
$EditarPorEmail = (isset($_POST['EditarPorEmail'])) ? $_POST['EditarPorEmail'] : 'N';
$EditarPorSMS = (isset($_POST['EditarPorSMS'])) ? $_POST['EditarPorSMS'] : 'N';
$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
$EditarSobrenome = (isset($_POST['EditarSobrenome'])) ? $_POST['EditarSobrenome'] : '';
$EditarUsuario = (isset($_POST['EditarUsuario'])) ? $_POST['EditarUsuario'] : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
$EditarEmail = (isset($_POST['EditarEmail'])) ? $_POST['EditarEmail'] : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? $_POST['EditarCelular'] : '';
$EditarPrePago = (isset($_POST['EditarPrePago'])) ? $_POST['EditarPrePago'] : 'N';
$EditarPremium = (isset($_POST['EditarPremium'])) ? $_POST['EditarPremium'] : '';
$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
$EditarValorCobradoCabo = (isset($_POST['EditarValorCobradoCab'])) ? ConverterDinheiro($_POST['EditarValorCobradoCab']) : '';
$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
$EditarCota = (isset($_POST['EditarCota'])) ? $_POST['EditarCota'] : 0;
$EditarTempo = (isset($_POST['EditarTempo'])) ? $_POST['EditarTempo'] : 0;
$CadUser = InfoUser(2);
$acesso = InfoUser(3);	
$VerificarEmailUser = VerificarEmailUser($CadUser, 'DadosDeAcesso');
$VerificarSMSUser = VerificarSMSUser($CadUser, 'DadosDeAcesso');

$VerificarCaracterUsuario = VerificarCaracter($EditarUsuario);
$VerificarCaracterSenha = VerificarCaracter($EditarSenha);

	$VerificarInfoPre = VerificarInfoPre();
	
	$VerificarLimiteTeste = VerificarLimiteTeste($CadUser);
	
	if( ($VerificarLimiteTeste != 0) && ($EditarLimiteTeste > $VerificarLimiteTeste) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ldtnpvpanm'].$VerificarLimiteTeste, "danger");
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
	elseif( ($EditarPrePago == "N") && empty($EditarPremium) && ($VerificarInfoPre[0] == "N") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dpeuco'], "danger");
	}
	elseif( empty($EditarCota) && ($VerificarInfoPre[0] == "S") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['coeuco'], "danger");
	}
	elseif( ($VerificarInfoPre[0] == "S") && ($VerificarInfoPre[1] < $EditarCota) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['vntcs'], "danger");
	}
	elseif( !empty($EditarCota) && (is_numeric($EditarCota) == false) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cotadcan'], "danger");
	}
	elseif( !empty($EditarTempo) && is_numeric($EditarTempo) == false ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['temdcan'], "danger");
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
	
	if($VerificarInfoPre[0] == "S"){
		$EditarPrePago = $VerificarInfoPre[0];
		$EditarTempo = $VerificarInfoPre[2];
		$NovaCota = $VerificarInfoPre[1] - $EditarCota;
		
		$SQLRev = "UPDATE rev SET
			Cota = :Cota
            WHERE usuario = :usuario";
		$SQLRev = $painel_user->prepare($SQLRev);                                  
		$SQLRev->bindValue(':Cota', $NovaCota); 
		$SQLRev->bindValue(':usuario', $CadUser); 
		$SQLRev->execute();
		
		$_SESSION['Cota'] = $NovaCota;
	}
	
	if($EditarPrePago == "S"){
		$EditarPremium = "";
	}
	else{
		$EditarPremium = ConverterData($EditarPremium, 2);
		$EditarPremium = strtotime($EditarPremium);
	}
	
	$ArrayEditarPerfil = $EditarPerfil;
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	$DataAtual = date('Y-m-d H:i:s');
			
	$SQL = "INSERT INTO rev (
			CadUser,
			nome,
            sobrenome,
            usuario,
			senha,
			email,
			celular,
			perfil,
			data_cadastro,
			data_premio,
			VencEmail,
			VencSMS,
			PrePago,
			Cota,
			CotaDias,
			ValorCobrado,
			ValorCobradoCabo,
			obs,
			LimiteTeste
            ) VALUES (
			:CadUser,
			:nome,
            :sobrenome,
            :usuario,
			:senha,
			:email,
			:celular,
			:perfil,
			:data_cadastro,
			:data_premio,
			:VencEmail,
			:VencSMS,
			:PrePago,
			:Cota,
			:CotaDias,
			:ValorCobrado,
			:ValorCobradoCabo,
			:obs,
			:LimiteTeste
			)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':sobrenome', $EditarSobrenome, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $EditarUsuario, PDO::PARAM_STR); 
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR);
	$SQL->bindParam(':celular', $EditarCelular, PDO::PARAM_STR); 
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(':data_cadastro', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR);
	$SQL->bindParam(':VencEmail', $EditarPorEmail, PDO::PARAM_STR);
	$SQL->bindParam(':VencSMS', $EditarPorSMS, PDO::PARAM_STR);
	$SQL->bindParam(':PrePago', $EditarPrePago, PDO::PARAM_STR);
	$SQL->bindParam(':Cota', $EditarCota, PDO::PARAM_STR);
	$SQL->bindParam(':CotaDias', $EditarTempo, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobrado', $EditarValorCobrado, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobradoCabo', $EditarValorCobradoCabo, PDO::PARAM_STR);
	$SQL->bindParam(':obs', $obs, PDO::PARAM_STR);
	$SQL->bindParam(':LimiteTeste', $EditarLimiteTeste, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if($EditarPrePago == "S"){
		$Scota = $EditarCota > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
		$STempo = $EditarTempo > 1 ? $_TRA['dias'] : $_TRA['dia'];
		$VcCli = $EditarCota." ".$Scota." (".$EditarTempo." ".$STempo.")";
	}
	else{
		$VcCli = date('d/m/Y', $EditarPremium);
	}
	
	if( ($EnviarEmail == "on") && !empty($EditarEmail)){
		$SelecionarModelo = SelecionarModelo($CadUser, 'DadosDeAcesso', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		
		$bloqueado = "N";
		$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
		$SQLUser = $painel_geral->prepare($SQLUser);
		$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $EditarEmail, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	if( ($EnviarSMS == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, 'DadosDeAcesso', $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	if( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeueeus'], "success", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeueeus'], "warning", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccseecsoueaeos'], "warning", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeoesecs'], "warning", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeue'], "success", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeus'], "success", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) ){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeoe'], "warning", "index.php?p=revendedor");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeos'], "warning", "index.php?p=revendedor");
		exit;
	}
	
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=revendedor");
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