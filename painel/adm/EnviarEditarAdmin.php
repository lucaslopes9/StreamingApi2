<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminEditar');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminEditar = $VerificarAcesso[0];

if($AdminEditar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$obs = (isset($_POST['obs'])) ? $_POST['obs'] : '';
$EditarUsuario = (isset($_POST['EditarUsuario'])) ? $_POST['EditarUsuario'] : '';
$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
$EditarSobrenome = (isset($_POST['EditarSobrenome'])) ? $_POST['EditarSobrenome'] : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
$EditarEmail = (isset($_POST['EditarEmail'])) ? $_POST['EditarEmail'] : '';
$EditarCelular = (isset($_POST['EditarCelular'])) ? $_POST['EditarCelular'] : '';
$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
$EditarValorCobradoCab = (isset($_POST['EditarValorCobradoCab'])) ? ConverterDinheiro($_POST['EditarValorCobradoCab']) : '';
$UsuarioOnline = InfoUser(2);

$ArvoreAdminOnline = ArvoreAdmin($UsuarioOnline);
$ArvoreAdminOnline[] = $UsuarioOnline;


	if(!in_array($EditarUsuario, $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$EditarUsuario,$_TRA['npounpav']), "danger");
	}
	elseif(empty($EditarSenha) && ($UsuarioOnline != $EditarUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	elseif(empty($EditarEmail)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( substr_count($EditarEmail, "@") == 0 || !empty($EditarEmail) && substr_count($EditarEmail, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif(!empty($EditarCelular) && is_numeric(LimparCelular($EditarCelular)) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	else{
	
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
		
	if($UsuarioOnline != $EditarUsuario){
		$SQL = "UPDATE admin SET
		nome = :nome,
		sobrenome = :sobrenome,
		senha = :senha,
		email = :email,
		celular = :celular,
		perfil = :perfil,
		ValorCobrado = :ValorCobrado,
		ValorCobradoCabo = :ValorCobradoCabo,
		obs = :obs
        WHERE usuario = :usuario";
	}
	else{
		$SQL = "UPDATE admin SET
		nome = :nome,
		sobrenome = :sobrenome,
		email = :email,
		celular = :celular,
		perfil = :perfil,
		ValorCobrado = :ValorCobrado,
		ValorCobradoCabo = :ValorCobradoCabo,
		obs = :obs
        WHERE usuario = :usuario";
	}
			
			
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':sobrenome', $EditarSobrenome, PDO::PARAM_STR); 
	if($UsuarioOnline != $EditarUsuario) $SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR);
	$SQL->bindParam(':celular', $EditarCelular, PDO::PARAM_STR); 
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobrado', $EditarValorCobrado, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobradoCabo', $EditarValorCobradoCab, PDO::PARAM_STR);
	$SQL->bindParam(':obs', $obs, PDO::PARAM_STR);
	$SQL->bindParam(':usuario', $EditarUsuario, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=administrador");
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