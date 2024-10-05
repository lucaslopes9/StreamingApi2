<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$old_password = (isset($_POST['old_password'])) ? $_POST['old_password'] : '';
$new_password = (isset($_POST['new_password'])) ? $_POST['new_password'] : '';
$re_password = (isset($_POST['re_password'])) ? $_POST['re_password'] : '';

	if(empty($old_password)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['saco'], "danger");
	}
	elseif(empty($new_password)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nsco'], "danger");
	}
	elseif(empty($re_password)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['rnsco'], "danger");
	}
	elseif($new_password != $re_password){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nsrnsco'], "danger");
	}
	elseif(SenhaAtual() == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['senhabranco'], "danger");
	}
	elseif(SenhaAtual() != $old_password){
		echo MensagemAlerta($_TRA['erro'], $_TRA['senhanc'], "danger");
	}
	else{
		
	$id_user = InfoUser(1);
	$usuario = InfoUser(2);
	$SQL = "UPDATE ".SelectTabela()." SET
			senha = :senha
            WHERE id = :id AND usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':senha', $new_password, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id_user, PDO::PARAM_INT); 
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['sacs'], "success");
	}
		
		
	}
}

}

?>