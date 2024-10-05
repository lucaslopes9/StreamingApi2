<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	 
$email = (isset($_POST['email'])) ? $_POST['email'] : '';

	if(empty($email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif(!empty($email) && substr_count($email, "@") == 0 || !empty($email) && substr_count($email, ".") == 0) { 
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	else{
				
	$id_user = InfoUser(1);
	$usuario = InfoUser(2);
	$SQL = "UPDATE ".SelectTabela()." SET
			email = :email
            WHERE id = :id AND usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':email', $email, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id_user, PDO::PARAM_INT); 
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	$_SESSION['email'] = $email;
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['eacs'], "success", "index.php?p=editar-perfil");
	}
		
		
	}
}

}

?>