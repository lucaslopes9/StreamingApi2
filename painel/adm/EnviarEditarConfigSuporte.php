<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$ExibirPorPag = (isset($_POST['ExibirPorPag'])) ? $_POST['ExibirPorPag'] : '';

	if(empty($ExibirPorPag)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eppeuco'], "danger");
	}
	else{
		
	
	$user = InfoUser(2);
	$SQLSup = "SELECT id FROM config_suporte WHERE CadUser = :CadUser";
	$SQLSup = $painel_geral->prepare($SQLSup);
	$SQLSup->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLSup->execute();
	$TotalSup = count($SQLSup->fetchAll());
	
	if($TotalSup > 0){
		$SQL = "UPDATE config_suporte SET
			SuportePaginacao = :SuportePaginacao
            WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':SuportePaginacao', $ExibirPorPag, PDO::PARAM_INT);
		$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	else{
		$SQL = "INSERT INTO config_suporte (
			CadUser,
			SuportePaginacao
            ) VALUES (
			:CadUser,
            :SuportePaginacao
			)";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
		$SQL->bindParam(':SuportePaginacao', $ExibirPorPag, PDO::PARAM_INT);
		$SQL->execute();
	}
	
	$_SESSION['SuportePaginacao'] = $ExibirPorPag;
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=suporte");
	}
		
		
	}
}

}else{
	echo Redirecionar('login.php');
}

?>