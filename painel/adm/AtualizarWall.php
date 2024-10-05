<?php
include("conexao.php");
include_once("functions.php");

if(ProtegePag() == true){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$wall = (isset($_POST['wall'])) ? $_POST['wall'] : '';
	$_SESSION['wall'] = $wall;

	
	$user = InfoUser(2);
	$SQLLeiaute = "SELECT id FROM leiaute WHERE CadUser = :CadUser";
	$SQLLeiaute = $painel_geral->prepare($SQLLeiaute);
	$SQLLeiaute->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLLeiaute->execute();
	$TotalLeiaute = count($SQLLeiaute->fetchAll());

	$user = InfoUser(2);
	if($TotalLeiaute > 0){
	$SQL = "UPDATE leiaute SET
			wall = :wall
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':wall', $wall, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO leiaute (
			CadUser,
			wall
            ) VALUES (
			:CadUser,
            :wall
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
	$SQL->bindParam(':wall', $wall, PDO::PARAM_STR);
	$SQL->execute(); 
	}
		
}

}

?>