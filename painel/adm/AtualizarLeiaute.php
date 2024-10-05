<?php
include("conexao.php");
include_once("functions.php");

if(ProtegePag() == true){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$leiaute = (isset($_POST['leiaute'])) ? $_POST['leiaute'] : '';
	$_SESSION['leiaute'] = $leiaute;
	
	$user = InfoUser(2);
	$SQLLeiaute = "SELECT id FROM leiaute WHERE CadUser = :CadUser";
	$SQLLeiaute = $painel_geral->prepare($SQLLeiaute);
	$SQLLeiaute->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLLeiaute->execute();
	$TotalLeiaute = count($SQLLeiaute->fetchAll());
	
	$user = InfoUser(2);
	if($TotalLeiaute > 0){
	$SQL = "UPDATE leiaute SET
			leiaute = :leiaute
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':leiaute', $leiaute, PDO::PARAM_INT);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO leiaute (
			CadUser,
			leiaute
            ) VALUES (
			:CadUser,
            :leiaute
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
	$SQL->bindParam(':leiaute', $leiaute, PDO::PARAM_INT);
	$SQL->execute(); 
	}
		
}

}

?>