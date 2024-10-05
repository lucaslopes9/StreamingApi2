<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$Coluna_1 = array('AdminVisualizar');
$VerificarAcesso_1 = VerificarAcesso('admin', $Coluna_1);
$AdminVisualizar = $VerificarAcesso_1[0];

$Coluna_8 = array('RevVisualizar');
$VerificarAcesso_8 = VerificarAcesso('rev', $Coluna_8);
$RevVisualizar = $VerificarAcesso_8[0];
	
$Coluna_9 = array('UserVisualizar');
$VerificarAcesso_9 = VerificarAcesso('user', $Coluna_9);
$UserVisualizar = $VerificarAcesso_9[0];
	
$Coluna_10 = array('TesteVisualizar');
$VerificarAcesso_10 = VerificarAcesso('teste', $Coluna_10);
$TesteVisualizar = $VerificarAcesso_10[0];

if( ($AdminVisualizar == 'S') || ($RevVisualizar == 'S') || ($UserVisualizar == 'S') || ($TesteVisualizar == 'S') ){ 

$VerificarInfoPre = VerificarInfoPre();
	
// storing  request (ie, get/post) global array to a variable  
$requestData= $_REQUEST;

$columns = array( 
	2 => 'nome',
	3=> 'usuario',
	4=> 'senha',
	5=> 'email',
	6=> 'perfil',
	7=> 'conexao',
	8=> 'data_premio',
	9=> 'CadUser',
);

$CadUser = InfoUser(2);
	
$SQL = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular, grupo, PrePago FROM (
SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular, grupo, PrePago FROM admin 
UNION ALL 
SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular, grupo, PrePago FROM rev 
UNION ALL 
SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular, grupo, PrePago FROM teste 
UNION ALL 
SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular, grupo, PrePago FROM usuario) as newt WHERE newt.CadUser = :CadUser";
	
$SQLUser = $painel_user->prepare($SQL);
$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLUser->execute();
$totalData = count($SQLUser->fetchAll());
$totalFiltered = $totalData;


if( !empty($requestData['search']['value']) ) {
	
	$SQL.=" AND (newt.nome LIKE '%".$requestData['search']['value']."%'";    
	$SQL.=" OR newt.usuario LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR newt.senha LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR newt.email LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR newt.perfil LIKE '%".$requestData['search']['value']."%' )";
	
	$SQLss = $painel_user->prepare($SQL);
	$SQLss->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLss->execute();
	$totalFiltered = count($SQLss->fetchAll());	
}

$order = " ORDER by newt.id DESC";
$ColunaRequest = $requestData['order'][0]['column'];
if( ($ColunaRequest == 2) || ($ColunaRequest == 3) || ($ColunaRequest == 4) || ($ColunaRequest == 5) || ($ColunaRequest == 6) || ($ColunaRequest == 7) || ($ColunaRequest == 8) || ($ColunaRequest == 9) ){
	$order = " ORDER BY ". $columns[$requestData['order'][0]['column']]." ".$requestData['order'][0]['dir'];
}

$SQL .= $order." LIMIT ".$requestData['start']." ,".$requestData['length']."";

$SQL = $painel_user->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();

$data = array();
while($LnUser = $SQL->fetch()){
	
	if($LnUser['bloqueado'] == "S"){
		$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
	}else{
		$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloqueado']."\">".$_TRA['desbloqueado'][0]."</span>";
	}
	
	if(empty($LnUser['perfil'])){
		$perfil = "";
	}
	else{
		$perfil = SelecionarPerfil($LnUser['perfil']);
	}
		
	$Foto = Foto($LnUser['foto']);
	$Foto1 = "<img class=\"pointer\" src=\"".$Foto."\" alt=\"".$LnUser['nome']."\" height=\"32\" width=\"32\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['nome']."\">";
	
	if(!empty($LnUser['email'])){
    	$EmailUser = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['email']."\"><i class=\"fa fa-at\"></i></span>";
	}
	else{
		$EmailUser = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['eunpede']."\"><i class=\"fa fa-at\"></i></span>";
	}
	
	$PerfilUser = "<div class=\"form-group\">".$perfil."</div>";
	
	$sconexao = $LnUser['conexao'] > 1 ? $_TRA['conexoes'] : $_TRA['conexao'];
	$pconexao = empty($LnUser['conexao']) ? 0 : $LnUser['conexao'];
	$conexao = "<span class=\"pointer label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$pconexao." ".$sconexao."\">".$pconexao."</span>";
	
	
	$UserOpcoes = "<div class=\"form-group\">";
	
	if($LnUser['grupo'] == 1){
		$UserOpcoes .= "-";
	}
	else{
		
		if($LnUser['grupo'] == 2){
			$linkuser = "index.php?p=revendedor&user=".$LnUser['usuario']."";
		}
		elseif($LnUser['grupo'] == 3){
			$linkuser = "index.php?p=usuario&user=".$LnUser['usuario']."";
		}
		elseif($LnUser['grupo'] == 4){
			$linkuser = "index.php?p=teste&user=".$LnUser['usuario']."";
		}
		else{
			$linkuser = "index.php?p=usuario&user=".$LnUser['usuario']."";
		}
		
		$UserOpcoes .= "<a href=\"".$linkuser."\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Exibir\"><i class=\"fa fa-angle-double-right\"></i></a>&nbsp;";
	}
											
	$UserOpcoes .= "</div>";
	
	if( ($LnUser['PrePago'] == "S") || ($LnUser['grupo'] == 1) ){
			$Premium = "-";
	}
	else{
		
		$ConvertDataPremium = ConvertDataPremium($LnUser['data_premio']);
		
		if($LnUser['xml'] == "S"){
			$Premium = "<span id=\"StatusDerrubar".$LnUser['id']."\"><span onclick=\"XMLUserRem('".$LnUser['usuario']."', 'StatusDerrubar".$LnUser['id']."');\" class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['anx']."\">".$_TRA['anx'][0]."</span></span>&nbsp;".$ConvertDataPremium;
		}
		else{
			$Premium = "<span id=\"StatusDerrubar".$LnUser['id']."\"><span onclick=\"XMLUserAdd('".$LnUser['usuario']."', 'StatusDerrubar".$LnUser['id']."');\" class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['fdx']."\">".$_TRA['fdx'][0]."</span></span>&nbsp;".$ConvertDataPremium;
		}
	}
		
	if($LnUser['grupo'] == 1){
		$grupo_title = "Administrador";
		$grupo_number = 1;
		$grupo_status = "danger";
		$conexao = "-";
	}
	elseif($LnUser['grupo'] == 2){
		$grupo_title = "Revendedor";
		$grupo_number = 2;
		$grupo_status = "warning";
		$conexao = "-";
	}
	elseif($LnUser['grupo'] == 3){
		$grupo_title = "Usuário";
		$grupo_number = 3;
		$grupo_status = "info";
	}
	else{
		$grupo_title = "Teste";
		$grupo_number = 4;
		$grupo_status = "primary";
	}
	$grupos = "<span class=\"pointer label label-".$grupo_status."\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$grupo_title."\">$grupo_number</span>";
		
	$nestedData=array(); 

	$nestedData[] = $grupos;
	$nestedData[] = $Foto1;
	$nestedData[] = $LnUser['nome'].$status;
	$nestedData[] = $LnUser['usuario'];
	$nestedData[] = $LnUser['senha'];
	$nestedData[] = $EmailUser;
	$nestedData[] = $PerfilUser;
	$nestedData[] = $conexao;
	$nestedData[] = $Premium;
	$nestedData[] = $CadUser;
	$nestedData[] = $UserOpcoes;
	
	$data[] = $nestedData;
}

$json_data = array(
			"draw"            => intval( $requestData['draw'] ),   // for every request/draw by clientside , they send a number as a parameter, when they recieve a response/data they first check the draw number, so we are sending same number in draw. 
			"recordsTotal"    => intval( $totalData ),  // total number of records
			"recordsFiltered" => intval( $totalFiltered ), // total number of records after searching, if there is no searching then totalFiltered = totalData
			"data"            => $data   // total data array
			);

echo json_encode($json_data);  // send data as json format

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>