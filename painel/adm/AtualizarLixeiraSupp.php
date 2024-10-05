<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$SelectBox = (isset($_POST['SelectBox'])) ? $_POST['SelectBox'] : '';
	
	if(empty($SelectBox)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	$user = InfoUser(2);
	$Pasta = 4;
	
	$SQL = "UPDATE suporte SET
			PastaReceptor = :PastaReceptor
            WHERE id = :id AND UserReceptor = :UserReceptor";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':PastaReceptor', $Pasta, PDO::PARAM_INT);
	$SQL->bindParam(':id', $SelectBox, PDO::PARAM_INT);
	$SQL->bindParam(':UserReceptor', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	$SQL = "UPDATE suporte SET
			PastaEmissor = :PastaEmissor
            WHERE id = :id AND UserEmissor = :UserEmissor";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':PastaEmissor', $Pasta, PDO::PARAM_INT);
	$SQL->bindParam(':id', $SelectBox, PDO::PARAM_INT);
	$SQL->bindParam(':UserEmissor', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=suporte");
	}
	
	}
		
}

}

?>