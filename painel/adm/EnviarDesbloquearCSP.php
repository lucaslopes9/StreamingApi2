<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspBloquear');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspBloquear = $VerificarAcesso[0];

if($ServidorcspBloquear == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$bloqueado = "N";
	$SQL = "UPDATE painel SET
			block = :block
            WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':block', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['dcs'], "success", "index.php?p=csp");
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