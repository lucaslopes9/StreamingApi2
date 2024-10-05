<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array("UserEditar");
$VerificarAcesso = VerificarAcesso("user", $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == "S"){

if ($_SERVER["REQUEST_METHOD"] == "POST") {

$EnviarCOM = (isset($_POST["EnviarCOM"])) ? htmlentities($_POST["EnviarCOM"]) : "";
$obs = (isset($_POST["obs"])) ? htmlentities($_POST["obs"]) : "";
$EnviarEmailRen = (isset($_POST["EnviarEmailRen"])) ? $_POST["EnviarEmailRen"] : "off";
$EnviarSMSRen = (isset($_POST["EnviarSMSRen"])) ? $_POST["EnviarSMSRen"] : "off";
$XML = (isset($_POST["XML"])) ? $_POST["XML"] : "N";
$IDUsuario = (isset($_POST["IDUsuario"])) ? $_POST["IDUsuario"] : "";
$Usuario = (isset($_POST["Usuario"])) ? htmlentities($_POST["Usuario"]) : "";
$EnviarEmail = (isset($_POST["EnviarEmail"])) ? $_POST["EnviarEmail"] : "off";
$EnviarSMS = (isset($_POST["EnviarSMS"])) ? $_POST["EnviarSMS"] : "off";
$EditarPorEmail = (isset($_POST["EditarPorEmail"])) ? $_POST["EditarPorEmail"] : "N";
$EditarPorSMS = (isset($_POST["EditarPorSMS"])) ? $_POST["EditarPorSMS"] : "N";
$EditarNome = (isset($_POST["EditarNome"])) ? htmlentities($_POST["EditarNome"]) : "";
$EditarSobrenome = (isset($_POST["EditarSobrenome"])) ? htmlentities($_POST["EditarSobrenome"]) : "";
$EditarSenha = (isset($_POST["EditarSenha"])) ? htmlentities($_POST["EditarSenha"]) : "";
$EditarEmail = (isset($_POST["EditarEmail"])) ? $_POST["EditarEmail"] : "";
$EditarCelular = (isset($_POST["EditarCelular"])) ? htmlentities($_POST["EditarCelular"]) : "";
$EditarPremium = (isset($_POST["EditarPremium"])) ? htmlentities($_POST["EditarPremium"]) : "";
$EditarValorCobrado = (isset($_POST["EditarValorCobrado"])) ? ConverterDinheiro(htmlentities($_POST["EditarValorCobrado"])) : "";
$ValorCobrado = (isset($_POST["ValorCobrado"])) ? ConverterDinheiro(htmlentities($_POST["ValorCobrado"])) : "";
$EditarPerfil = (isset($_POST["EditarPerfil"])) ? $_POST["EditarPerfil"] : "";
$EditarConexao = (isset($_POST["EditarConexao"])) ? htmlentities($_POST["EditarConexao"]) : 0;
$CadUser = InfoUser(2);
$acesso = InfoUser(3);	
$VerificarEmailUser = VerificarEmailUser($CadUser, "DadosDeAcesso");
$VerificarSMSUser = VerificarSMSUser($CadUser, "DadosDeAcesso");
$VerificarEmailUserRen = VerificarEmailUser($CadUser, "Renovacao");
$VerificarSMSUserRen = VerificarSMSUser($CadUser, "Renovacao");

$VerificarCaracterSenha = VerificarCaracter($EditarSenha);

	$ArvoreAdminOnline = ArvoreAdminRev($CadUser);
	$ArvoreAdminOnline[] = $CadUser;
	
	$SQLUser = "SELECT CadUser FROM usuario WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(":usuario", $Usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	$VerificarInfoPre = VerificarInfoPre();
	if($VerificarInfoPre[0] == "S") {
		
		$SQLTempo = "SELECT data_premio, conexao FROM usuario WHERE id = :id";
		$SQLTempo = $painel_user->prepare($SQLTempo);
		$SQLTempo->bindParam(":id", $IDUsuario, PDO::PARAM_STR);
		$SQLTempo->execute();
		$LnTempo = $SQLTempo->fetch();
		$data_premio = empty($LnTempo["data_premio"]) ? 0 : $LnTempo["data_premio"];
		$Userconexao = empty($LnTempo["conexao"]) ? 0 : $LnTempo["conexao"];
		
		$NovaCota = ($VerificarInfoPre[1] + $Userconexao) - $EditarConexao;
	}
	
	if(!in_array($LnUser["CadUser"], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA["erro"], str_replace("USER_TAG",$Usuario,$_TRA["npounpav"]), "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA["erro"], $_TRA["cvfi"], "danger");
	}
	elseif(empty($EditarSenha)){
		echo MensagemAlerta($_TRA["erro"], $_TRA["SCO"], "danger");
	}
	elseif(substr_count($EditarSenha, " ") > 0){
		echo MensagemAlerta($_TRA["erro"], $_TRA["snpce"], "danger");
	}
	elseif(!empty($VerificarCaracterSenha[0])){
		echo MensagemAlerta($_TRA["erro"], $_TRA["snpcec"].$VerificarCaracterSenha[1], "danger");
	}
	elseif( !empty($EditarEmail) && substr_count($EditarEmail, "@") == 0 || !empty($EditarEmail) && substr_count($EditarEmail, ".") == 0) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dei"], "danger");
	}
	elseif( !empty($EditarCelular) && (is_numeric(LimparCelular($EditarCelular)) == false) ){
		echo MensagemAlerta($_TRA["erro"], $_TRA["cdcan"], "danger");
	}
	elseif( empty($EditarConexao) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["ceuco"], "danger");
	}
	elseif( is_numeric($EditarConexao) == false ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["codcan"], "danger");
	}
	elseif( empty($EditarPremium) && ($VerificarInfoPre[0] == "N")  ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dpeuco"], "danger");
	}
	elseif( ($VerificarInfoPre[0] == "S") && ($NovaCota < 0) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["vntcs"], "danger");
	}
	elseif( !empty($EditarValorCobrado) && strlen(str_replace(".","",ConverterDinheiro($EditarValorCobrado))) > 5 ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["vsnpcmdq5d"], "danger");
	}
	elseif( !empty($ValorCobrado) && strlen(str_replace(".","",ConverterDinheiro($ValorCobrado))) > 5 ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["vcabnpcmdq5d"], "danger");
	}
	elseif( empty($EditarPerfil) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["sepmup"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailRen == "on") ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["psautsedoernpodamt"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSRen == "on") ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["psautsedoernpodamtsms"], "danger");
	}
	elseif( ($EnviarEmail == "on") && empty($EditarEmail) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["euco"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 1) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cueeeacq"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 2) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["oeaesb"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 3) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["nenmdea"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 4) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dapdmdepd"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 5) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omanemdnapme"], "danger");
	}
	elseif( ($EnviarEmail == "on") && ($VerificarEmailUser == 6) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omaebrode"], "danger");
	}
	elseif( ($EnviarSMS == "on") && empty($EditarCelular) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cuco"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 1) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cucdsesa"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 2) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["acsaesbrode"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 3) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["nenmdsapasm"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 4) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dapdmdspdsm"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 5) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omanemdnapdmdspd"], "danger");
	}
	elseif( ($EnviarSMS == "on") && ($VerificarSMSUser == 6) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omadsebrodesm"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && empty($EditarEmail) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["euco"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 1) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cueeeacq"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 2) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["oeaesb"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 3) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["nenmdea"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 4) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dapdmdepd"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 5) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omanemdnapme"], "danger");
	}
	elseif( ($EnviarEmailRen == "on") && ($VerificarEmailUserRen == 6) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omaebrode"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && empty($EditarCelular) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cuco"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 1) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["cucdsesa"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 2) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["acsaesbrode"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 3) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["nenmdsapasm"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 4) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["dapdmdspdsm"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 5) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omanemdnapdmdspd"], "danger");
	}
	elseif( ($EnviarSMSRen == "on") && ($VerificarSMSUserRen == 6) ) {
		echo MensagemAlerta($_TRA["erro"], $_TRA["omadsebrodesm"], "danger");
	}
	else{		
		
	$EditarPremium = ConverterData($EditarPremium, 2);
	$EditarPremium = strtotime($EditarPremium);
	
	$ArrayEditarPerfil = $EditarPerfil;
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	
	if($VerificarInfoPre[0] == "S"){
		$EditarPremium = empty($data_premio) ? time() + (3600 * 24 * $VerificarInfoPre[2]) : $data_premio;
		
		$SQLRev = "UPDATE rev SET
			Cota = :Cota
            WHERE usuario = :usuario";
		$SQLRev = $painel_user->prepare($SQLRev);                                  
		$SQLRev->bindValue(":Cota", $NovaCota); 
		$SQLRev->bindValue(":usuario", $CadUser); 
		$SQLRev->execute();
		
		$_SESSION["Cota"] = $NovaCota;
	}
	
	if (time() < $EditarPremium){
		
	$SQL = "UPDATE usuario SET
				nome = :nome,
				sobrenome = :sobrenome,
				senha = :senha,
				email = :email,
				celular = :celular,
				conexao = :conexao,
				perfil = :perfil,
				data_premio = :data_premio,
				VencEmail = :VencEmail,
				VencSMS = :VencSMS,
				ValorCobrado = :ValorCobrado,
				ValorCobradoCab = :ValorCobradoCab,
				xml = :xml,
				obs = :obs
        	WHERE id = :id";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(":nome", $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(":sobrenome", $EditarSobrenome, PDO::PARAM_STR); 
	$SQL->bindParam(":senha", $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(":email", $EditarEmail, PDO::PARAM_STR);
	$SQL->bindParam(":celular", $EditarCelular, PDO::PARAM_STR); 
	$SQL->bindParam(":conexao", $EditarConexao, PDO::PARAM_STR); 
	$SQL->bindParam(":perfil", $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(":data_premio", $EditarPremium, PDO::PARAM_STR);
	$SQL->bindParam(":VencEmail", $EditarPorEmail, PDO::PARAM_STR);
	$SQL->bindParam(":VencSMS", $EditarPorSMS, PDO::PARAM_STR);
	$SQL->bindParam(":ValorCobrado", $EditarValorCobrado, PDO::PARAM_STR);
	$SQL->bindParam(":ValorCobradoCab", $ValorCobrado, PDO::PARAM_STR);
	$SQL->bindParam(":xml", $XML, PDO::PARAM_STR);
	$SQL->bindParam(":obs", $obs, PDO::PARAM_STR);
	$SQL->bindParam(":id", $IDUsuario, PDO::PARAM_STR);
	$SQL->execute(); 
	
	$SQLLogin = "SELECT usuario FROM usuario WHERE id = :id";
	$SQLLogin = $painel_user->prepare($SQLLogin);
	$SQLLogin->bindParam(":id", $IDUsuario, PDO::PARAM_STR);
	$SQLLogin->execute();
	$LnLogin = $SQLLogin->fetch();
	$EditarUsuario = $LnLogin["usuario"];
	
	$VcCli = date("d/m/Y", $EditarPremium);
	}
	//Email Acesso
	if( ($EnviarEmail == "on") && !empty($EditarEmail)){
		$SelecionarModelo = SelecionarModelo($CadUser, "DadosDeAcesso", $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
					
		$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
		$SQLUser = $painel_geral->prepare($SQLUser);
		$SQLUser->bindParam(":CadUser", $CadUser, PDO::PARAM_STR);
		$SQLUser->bindParam(":id", $EnviarCOM, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$EnviarEmailSend = EnviarEmail($LnUser["SMTPSecure"], $LnUser["Host"], $LnUser["Port"], $LnUser["usuario"], $LnUser["senha"], $LnUser["email"], $LnUser["exibicao"], $EditarEmail, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	//Email Renovação
	if( ($EnviarEmailRen == "on") && !empty($EditarEmail)){
		$SelecionarModelo = SelecionarModelo($CadUser, "Renovacao", $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		
		$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
		$SQLUser = $painel_geral->prepare($SQLUser);
		$SQLUser->bindParam(":CadUser", $CadUser, PDO::PARAM_STR);
		$SQLUser->bindParam(":id", $EnviarCOM, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$EnviarEmailSend = EnviarEmail($LnUser["SMTPSecure"], $LnUser["Host"], $LnUser["Port"], $LnUser["usuario"], $LnUser["senha"], $LnUser["email"], $LnUser["exibicao"], $EditarEmail, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	//SMS Acessos
	if( ($EnviarSMS == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, "DadosDeAcesso", $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	//SMS Renovação
	if( ($EnviarSMSRen == "on") && !empty($EditarCelular)){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, "Renovacao", $EditarUsuario, $EditarSenha, $EditarNome, $VcCli, $ArrayEditarPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $EditarCelular);
	}
	
	if( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsfeueeus"], "success", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsoueaeueeus"], "warning", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) && ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcseecsoueaeos"], "warning", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) && ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsoueaeoesecs"], "warning", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend == 1) ){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsfeue"], "success", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend == 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsfeus"], "success", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarEmail == "on") && ($EnviarEmailSend != 1) ){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsoueaeoe"], "warning", "index.php?p=usuario");
		exit;
	}
	elseif( ($EnviarSMS == "on") && ($EnviarSMSSend != 1)){
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcsoueaeos"], "warning", "index.php?p=usuario");
		exit;
	}
	
	
	if(empty($SQL) && time() < $EditarPremium){
		echo MensagemAlerta($_TRA["erro"], $_TRA["erropro"], "danger");
	}
	elseif(time() > $EditarPremium){
		echo MensagemAlerta($_TRA["erro"], "A data de vencimento deve ser maior que o dia atual!", "danger");
	}
	else{
		echo MensagemAlerta($_TRA["sucesso"], $_TRA["alcs"], "success", "index.php?p=usuario");
	}
		
		
	}
}

}else{
	echo Redirecionar("index.php");
}
}else{
	echo Redirecionar("login.php");
}	

?>
