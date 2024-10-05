<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
$GET = (isset($_POST['r'])) ? $_POST['r'] : '';
$CadUser = UrlTeste(2, $GET);
$VerTeste = VerTeste($CadUser);

//Verificar se o revendedor tem acessos para criar testes
$grupo = "N";
$SQLUrlT = "SELECT RevUrldeTeste FROM rev WHERE CadUser = :CadUser AND grupo = :grupo";
$SQLUrlT = $painel_acessos->prepare($SQLUrlT);
$SQLUrlT->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLUrlT->bindParam(':grupo', $grupo, PDO::PARAM_STR);
$SQLUrlT->execute();
$LnUrlT = $SQLUrlT->fetch();
$RevUrldeTeste = $LnUrlT['RevUrldeTeste'];

if( ($VerTeste[0] == 1) && ($RevUrldeTeste == "S") ){

$nome = (isset($_POST['nome'])) ? trim(htmlentities($_POST['nome'])) : '';
$email = (isset($_POST['email'])) ? trim(htmlentities($_POST['email'])) : '';
$celular = (isset($_POST['celular'])) ? trim(htmlentities($_POST['celular'])) : '';
$Operadora = (isset($_POST['Operadora'])) ? trim($_POST['Operadora']) : '';
$captcha = (isset($_POST['captcha'])) ? trim($_POST['captcha']) : '';
$CaptchaP = (isset($_COOKIE['CaptchaP'])) ? $_COOKIE['CaptchaP'] : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? trim(htmlentities($_POST['EditarCelular'])) : '';
$OpcaoForm = (isset($_POST['OpcaoForm'])) ? trim($_POST['OpcaoForm']) : '';
$cupom = (isset($_POST['cupom'])) ? trim(htmlentities($_POST['cupom'])) : '';
	
	$SQLEmailBanco = "SELECT email FROM bancoemail WHERE email = :email";
	$SQLEmailBanco = $painel_geral->prepare($SQLEmailBanco);
	$SQLEmailBanco->bindParam(':email', $email, PDO::PARAM_STR);
	$SQLEmailBanco->execute();
	$TotalEmailBanco = count($SQLEmailBanco->fetchAll());
	
	$SQLEmail = "SELECT email FROM teste WHERE email = :email";
	$SQLEmail = $painel_user->prepare($SQLEmail);
	$SQLEmail->bindParam(':email', $email, PDO::PARAM_STR);
	$SQLEmail->execute();
	$TotalEmail = count($SQLEmail->fetchAll());
	
	//Gerar Usuário
	$gerarNums = gerarNums(5, 0, 9, $email);
	
	$usuario = $gerarNums[0];
	$senha = $gerarNums[1];
	
	$VerificarTesteUsuario = VerificarTesteUsuario($usuario);
	$VerificarEmailUser = VerificarEmailUser($CadUser, 'DadosDeAcessoTeste');
	
	$VerificarLimiteTeste = VerificarLimiteTeste($CadUser);
	$VerificarCotaTeste = VerificarCotaTeste($CadUser);
	$CotaTesteDisponivel = $VerificarLimiteTeste - $VerificarCotaTeste;
	
	//Verifica E-mail Temporário
	
	$emailtemporario = "@".end(explode("@",$email));
			
	$SQLEmailTemp = "SELECT email FROM emailtemporario WHERE email = :email";
	$SQLEmailTemp = $painel_geral->prepare($SQLEmailTemp);
	$SQLEmailTemp->bindParam(':email', $emailtemporario, PDO::PARAM_STR);
	$SQLEmailTemp->execute();
	$TotalEmailTemp = count($SQLEmailTemp->fetchAll());
	
	$SQL = "SELECT status FROM captcha";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Ln = $SQL->fetch();
	$StatusCaptcha = $Ln['status'];
	
	$VerificarEmailTeste = VerificarEmailTeste($CadUser, $email);
	
	$TotalCupom = 0;
	if($OpcaoForm == "D"){
		$SQLCupom = "SELECT dias, perfil, UserDescontar FROM cupom WHERE Cupom = :Cupom";
		$SQLCupom = $painel_geral->prepare($SQLCupom);
		$SQLCupom->bindParam(':Cupom', $cupom, PDO::PARAM_STR);
		$SQLCupom->execute();
		$TotalCupom = count($SQLCupom->fetchAll());
	}
	
	if( ($TotalCupom == 0) && ($OpcaoForm == "D") ){
		echo MensagemAlerta($_TRA['erro'], "Cupom não existe!", "danger");
	}
	elseif( empty($captcha) && ($StatusCaptcha == "S") ){
		echo MensagemAlerta($_TRA['erro'], "Captcha é um campo obrigatório!", "danger");
	}
	elseif( empty($CaptchaP) && ($StatusCaptcha == "S") ){
		echo MensagemAlerta($_TRA['erro'], "Captcha Inválido!", "danger");
	}
	elseif( ($CaptchaP != $captcha) && ($StatusCaptcha == "S") ){
		echo MensagemAlerta($_TRA['erro'], "Captcha Inválido!", "danger");
	#}
	#elseif( ($TotalEmailTemp > 0) && ($VerificarEmailTeste == 0) ){
	#	echo MensagemAlerta($_TRA['erro'], $_TRA['nepccet'], "danger");
	}
	elseif( ($CotaTesteDisponivel < 1) && ($VerificarLimiteTeste != 0) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erntmldtdpftcutmt'], "danger");
	}
	elseif(empty($GET)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($nome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( substr_count($email, "@") == 0 || substr_count($email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif( substr_count($email, ">") > 0 || substr_count($email, "<") > 0 || substr_count($email, "\\") > 0) {
		echo MensagemAlerta($_TRA['erro'], 'Caracteres não permitidos no e-mail!', "danger");
	}
	elseif( ($TotalEmailBanco > 0) && ($VerificarEmailTeste == 0) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['utjfccee'], "danger");
	}
	elseif( ($TotalEmail > 0) && ($VerificarEmailTeste == 0) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eeeeu'], "danger");
	}
	elseif(empty($Operadora) && ($OpcaoForm == "T")){
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeuco'], "danger");
	}
	elseif(empty($cupom) && ($OpcaoForm == "D")){
		echo MensagemAlerta($_TRA['erro'], "Cupom é um campo obrigatório!", "danger");
	}
	elseif( !empty($EditarCelular) && (is_numeric(LimparCelular($EditarCelular)) == false) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	elseif($VerificarEmailUser == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($VerificarEmailUser == 2) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($VerificarEmailUser == 3) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($VerificarEmailUser == 4) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($VerificarEmailUser == 5) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($VerificarEmailUser == 6) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['osdtneccpfporpmi'], "danger");
	}
	elseif($TotalEmailTemp > 0){	
		
	if($OpcaoForm == "D"){
		$SQLCupom->execute();
		$LnCupom = $SQLCupom->fetch();
		$Dias = trim($LnCupom['dias']);
		$Operadora = trim($LnCupom['perfil']);
		$UserDescontar = trim($LnCupom['UserDescontar']);
		
		if(!empty($UserDescontar)){
			echo MensagemAlerta($_TRA['erro'], "Cupom inválido, já foi descontado!", "danger");	
			exit;
		}
		
		$DataAtual = time();
		$Premium = $DataAtual + (3600 * 24 * $Dias);
		$banco_base = "usuario";
	}
	else{
		$tempo = $VerTeste[1];
		$Premium = time() + (3600 * 24 * $tempo);
		$banco_base = "teste";
	}
	
	$DataAtual = date('Y-m-d H:i:s');
	$conexao = 1;
	$SQL = "INSERT INTO ".$banco_base." (
			CadUser,
			nome,
            usuario,
			senha,
			email,
			conexao,
			perfil,
			data_cadastro,
			data_premio,
			celular
            ) VALUES (
			:CadUser,
			:nome,
            :usuario,
			:senha,
			:email,
			:conexao,
			:perfil,
			:data_cadastro,
			:data_premio,
			:celular
			)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':nome', $nome, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQL->bindParam(':senha', $senha, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $email, PDO::PARAM_STR);
	$SQL->bindParam(':conexao', $conexao, PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $Operadora, PDO::PARAM_STR);
	$SQL->bindParam(':data_cadastro', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':data_premio', $Premium, PDO::PARAM_STR);
	$SQL->bindParam(':celular', $EditarCelular, PDO::PARAM_STR);
	$SQL->execute(); 
	
	//Cadastra no Banco de Email
	$SQLBanco = "INSERT INTO bancoemail (
			CadUser,
			email
            ) VALUES (
			:CadUser,
			:email
			)";
	$SQLBanco = $painel_geral->prepare($SQLBanco);
	$SQLBanco->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQLBanco->bindParam(':email', $email, PDO::PARAM_STR); 
	$SQLBanco->execute(); 
	
	$VcCli = date('d/m/Y', $Premium);
	$ArrayEditarPerfil = array();
	$ArrayEditarPerfil[] = $Operadora;
	
	if($OpcaoForm == "D"){
			$UserDescontarEm = time();
			$SQLCup = "UPDATE cupom SET
				UserDescontar = :UserDescontar,
				UserDescontarEm = :UserDescontarEm
				WHERE Cupom = :Cupom";
			$SQLCup = $painel_geral->prepare($SQLCup);
			$SQLCup->bindParam(':UserDescontar', $usuario, PDO::PARAM_STR); 
			$SQLCup->bindParam(':UserDescontarEm', $UserDescontarEm, PDO::PARAM_STR);
			$SQLCup->bindParam(':Cupom', $cupom, PDO::PARAM_STR); 
			$SQLCup->execute();
	}
	
	//Enviar E-mail
	$SelecionarModelo = SelecionarModelo($CadUser, 'DadosDeAcessoTeste', $usuario, $senha, $nome, $VcCli, $ArrayEditarPerfil);
		
	$bloqueado = "N";
	$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLUser = $painel_geral->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	$CopiaEmail = $VerTeste[2] == "S" && !empty($VerTeste[3]) ? $VerTeste[3] : NULL;
		
	$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $email, $SelecionarModelo[0], $SelecionarModelo[1], NULL, $CopiaEmail);
	//Enviar E-mail
	
	if(!empty($SQL) && $EnviarEmailSend == 1){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['acsfeue'], "success", "index.php?p=inicio");
	}
	elseif(!empty($SQL) && $EnviarEmailSend != 1){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccsoueaeoe'], "warning", "index.php?p=inicio");
	}
	else{
		if(empty($SQL)){
			echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], $_TRA['tccs'], "success", "index.php?p=inicio");
		}
	}
		
		
		}else{
			echo MensagemAlerta($_TRA['erro'], 'E-mail não permitido!', "danger");
		}

	}

}

?>