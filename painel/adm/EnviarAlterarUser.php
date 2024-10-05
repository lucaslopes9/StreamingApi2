<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$new_user = (isset($_POST['new_user'])) ? $_POST['new_user'] : '';
	$CadUser = InfoUser(2);
	$acesso = InfoUser(3);	

	if(empty($new_user)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nueuco'], "danger");
	}
	elseif (VerificarUsuarioEditar($new_user, NULL, $acesso) == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['uieeu'], "danger");
	}
	else{
	
	//Atualizar CadUser
	AtualizarUserBanco($CadUser, $new_user);
		
	$SQL = "UPDATE ".SelectTabela()." SET
				usuario = :UserNovo
           		WHERE usuario = :UserVelho";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':UserNovo', $new_user, PDO::PARAM_STR); 
	$SQL->bindParam(':UserVelho', $CadUser, PDO::PARAM_INT); 
	$SQL->execute();
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		$_SESSION['usuario'] = $new_user;
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['uacs'], "success", "index.php?p=editar-perfil");
	}
		
		
	}
}

}

?>