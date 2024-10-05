<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminAdicionar');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$obs = (isset($_POST['obs'])) ? $_POST['obs'] : '';
$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
$EditarSobrenome = (isset($_POST['EditarSobrenome'])) ? $_POST['EditarSobrenome'] : '';
$EditarUsuario = (isset($_POST['EditarUsuario'])) ? $_POST['EditarUsuario'] : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
$EditarEmail = (isset($_POST['EditarEmail'])) ? $_POST['EditarEmail'] : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? $_POST['EditarCelular'] : '';
$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
$EditarValorCobradoCab = (isset($_POST['EditarValorCobradoCab'])) ? ConverterDinheiro($_POST['EditarValorCobradoCab']) : '';
$CadUser = InfoUser(2);
$acesso = InfoUser(3);	

$VerificarCaracterUsuario = VerificarCaracter($EditarUsuario);
$VerificarCaracterSenha = VerificarCaracter($EditarSenha);
	
	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarNome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($EditarSobrenome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['suco'], "danger");
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
	elseif(empty($EditarEmail)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( substr_count($EditarEmail, "@") == 0 || substr_count($EditarEmail, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif( !empty($EditarCelular) && (is_numeric(LimparCelular($EditarCelular)) == false) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	else{
	
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	$DataAtual = date('Y-m-d H:i:s');
	
	$SQL = "INSERT INTO admin (
			CadUser,
			nome,
            sobrenome,
            usuario,
			senha,
			email,
			celular,
			perfil,
			data_cadastro,
			ValorCobrado,
			ValorCobradoCabo,
			obs
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
			:ValorCobrado,
			:ValorCobradoCabo,
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
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(':data_cadastro', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobrado', $EditarValorCobrado, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobradoCabo', $EditarValorCobradoCab, PDO::PARAM_STR);
	$SQL->bindParam(':obs', $obs, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=administrador");
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