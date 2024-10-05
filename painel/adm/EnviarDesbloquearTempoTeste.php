<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TesteTempoBloquear');
$VerificarAcesso = VerificarAcesso('tempoteste', $ColunaAcesso);
$SMSadicionarBloquear = $VerificarAcesso[0];

if($SMSadicionarBloquear == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$bloqueado = "N";	
	$SQL = "UPDATE tempoteste SET
			bloqueado = :bloqueado
            WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['dcs'], "success", "index.php?p=tempo-teste");
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