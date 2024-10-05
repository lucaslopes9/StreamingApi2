<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesGrupoAcesso');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesGrupoAcesso = $VerificarAcesso[0];
 
if($OpcoesGrupoAcesso == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$CadUser = InfoUser(2);
	$EditarNome = (isset($_POST['EditarNome'])) ? trim($_POST['EditarNome']) : "";
	
	$SQL = "SELECT nome FROM grupodeacesso WHERE nome = :nome AND CadUser = :CadUser AND id != :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute();
	$TotalNome = count($SQL->fetchAll());
	
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarNome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif($TotalNome > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['egdaje'], "danger");
	}
	else{
	
	$SQL = "UPDATE grupodeacesso SET
			nome = :nome
            WHERE id = :id AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=grupo-de-acesso");
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