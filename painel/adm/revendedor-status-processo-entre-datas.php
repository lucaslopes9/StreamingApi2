<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaRev = array('RevVisualizar', 'RevAcesso', 'RevInfo', 'RevMensagem', 'RevBloquear', 'RevDesativar', 'RevEditar', 'RevExcluir', 'RevAdicionar', 'RevLogin');
$VerificarAcesso = VerificarAcesso('rev', $ColunaRev);

$AdminVisualizar = $VerificarAcesso[0];
$AdminAcesso = $VerificarAcesso[1];
$AdminInfo = $VerificarAcesso[2];
$AdminMensagem = $VerificarAcesso[3];
$AdminBloquear = $VerificarAcesso[4];
$AdminDesativar = $VerificarAcesso[5];
$AdminEditar = $VerificarAcesso[6];
$AdminExcluir = $VerificarAcesso[7];
$AdminAdicionar = $VerificarAcesso[8];
$RevLogin = $VerificarAcesso[9];
 
if($AdminVisualizar == 'S'){

$requestData= $_REQUEST;
$CadUser = (isset($_GET['usuario'])) ? urldecode($_GET['usuario']) : '';
$status = (isset($_GET['status'])) ? urldecode($_GET['status']) : '';
$PerfilVer = (isset($_GET['perfil'])) ? urldecode($_GET['perfil']) : '';
$PesquisaEntreData = (isset($_GET['PesquisaEntreData'])) ? urldecode($_GET['PesquisaEntreData']) : '';
	
$DataExplode = explode(" - ",$PesquisaEntreData);
$DataInicial = trim($DataExplode[0]);
$DataFinal = trim($DataExplode[1]);

//Tratamento da Data Inicial
$TratarDataInicial = explode("/",$DataInicial);
$TratarDataInicialDia = trim($TratarDataInicial[0]);
$TratarDataInicialMes = trim($TratarDataInicial[1]);
$TratarDataInicialAno = trim($TratarDataInicial[2]);
	
$DataInicialOK = strtotime("".$TratarDataInicialAno."-".$TratarDataInicialMes."-".$TratarDataInicialDia."");
	
//Tratamento da Data Final
$TratarDataFinal = explode("/",$DataFinal);
$TratarDataFinalDia = trim($TratarDataFinal[0]);
$TratarDataFinalMes = trim($TratarDataFinal[1]);
$TratarDataFinalAno = trim($TratarDataFinal[2]);
	
$DataFinalOK = strtotime("".$TratarDataFinalAno."-".$TratarDataFinalMes."-".$TratarDataFinalDia."");
	
$PesquisarEntreDatasSQL = " AND data_premio > ".$DataInicialOK." AND data_premio < ".$DataFinalOK;
$PesquisarEntreDatasSQL2 = " AND data_premio = ".$DataInicialOK;
$PesquisarEntreDatasSQL3 = " AND data_premio = ".$DataFinalOK;
	
$columns = array( 
	2 => 'nome',
	3=> 'usuario',
	4=> 'senha',
	5=> 'email',
	6=> 'perfil',
	7=> 'data_premio',
	8=> 'CadUser'
);

$UserOnline = InfoUser(2);

if($status == "Ativos"){
	$DataAtual = strtotime(date('Y-m-d'));
	$PesStatus = " AND bloqueado = 'N' AND data_premio >= '".$DataAtual."'";
}
elseif($status == "Bloqueados"){
	$PesStatus = " AND bloqueado = 'S'";
}
elseif($status == "Inativos"){
	$PesStatus = " AND inativo = 'S'";
}
elseif($status == "Esgotados"){
	$DataAtual = strtotime(date('Y-m-d'));
	$PesStatus = " AND data_premio < '".$DataAtual."'";
}
else{
	$PesStatus = "";
}

if($PerfilVer == 'Todos'){
	$PesPerfil = "";
}
else{
	$PesPerfil = " AND perfil LIKE '%".$PerfilVer."%'";
}

if($CadUser == "Todos"){
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$SQL = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, inativo, data_premio, PrePago, Cota, CotaDias, celular FROM rev WHERE FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL." OR FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL2." OR FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL3."";
}else{	
	$SQL = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, inativo, data_premio, PrePago, Cota, CotaDias, celular FROM rev WHERE CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL." OR CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL2." OR CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL3."";
	}

	$SQLUser = $painel_user->prepare($SQL);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$totalData = count($SQLUser->fetchAll());
	$totalFiltered = $totalData;

if( !empty($requestData['search']['value']) ) {
	$SQL.=" AND (nome LIKE '%".$requestData['search']['value']."%'";    
	$SQL.=" OR usuario LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR senha LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR email LIKE '%".$requestData['search']['value']."%'";
	$SQL.=" OR perfil LIKE '%".$requestData['search']['value']."%' )";
	
	$SQLss = $painel_user->prepare($SQL);
	$SQLss->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLss->execute();
	$totalFiltered = count($SQLss->fetchAll());
}

$order = " ORDER by id DESC";
$ColunaRequest = $requestData['order'][0]['column'];
if( ($ColunaRequest == 2) || ($ColunaRequest == 3) || ($ColunaRequest == 4) || ($ColunaRequest == 5) || ($ColunaRequest == 6) || ($ColunaRequest == 7) || ($ColunaRequest == 8) ){
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
	
	if($LnUser['inativo'] == "S"){
		$statusA = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Desativado']."\">".$_TRA['Desativado'][0]."</span>";
	}else{
		$statusA = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
	}
	
	if(empty($LnUser['perfil'])){
		$perfil = "";
	}
	else{
		$perfil = SelecionarPerfil($LnUser['perfil']);
	}
	
	if($LnUser['PrePago'] == "S"){
		$Cotass = $LnUser['Cota'] > 1 ? $LnUser['Cota']." ".$_TRA['ccotas']."" : $LnUser['Cota']." ".$_TRA['ccota']."";
		$DiasCotass = $LnUser['CotaDias'] > 1 ? $LnUser['CotaDias']." ".$_TRA['dias']."" : $LnUser['CotaDias']." ".$_TRA['dia']."";	
											
		if($LnUser['Cota'] > 0){
			$dataPremium = "<span class=\"pointer label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$Cotass." (".$DiasCotass.")\">".$Cotass."</span>";
		}
		else{
			$dataPremium = "<td><span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Esgotado']."\">".$_TRA['Esgotado']."</span></td>";
		}								
	}
	else{
		$dataPremium =  ConvertDataPremium($LnUser['data_premio']);
	}
	
	$ICheckbox = ($CadUser == $LnUser['usuario']) ? "<input type=\"checkbox\" disabled>" : "<input type=\"checkbox\" class=\"MarcarTodos\" name=\"SelectUser[]\" id=\"SelectUser\" value=\"".$LnUser['usuario']."\" Onclick=\"VerificarCheck()\">";
	
	$Foto = Foto($LnUser['foto']);
	$Foto1 = "<img class=\"pointer\" src=\"".$Foto."\" alt=\"".$LnUser['nome']."\" height=\"32\" width=\"32\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['nome']."\">";
	
	if(!empty($LnUser['email'])){
    	$EmailUser = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['email']."\"><i class=\"fa fa-at\"></i></span>";
	}
	else{
		$EmailUser = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['eunpede']."\"><i class=\"fa fa-at\"></i></span>";
	}
	
	$PerfilUser = "<div class=\"form-group\">".$perfil."</div>";

	  $UserOpcoes = "<div class=\"form-group\">";
	  
	  if( ($CadUser != $LnUser['usuario']) && ($RevLogin == 'S')){
		$UserOpcoes .= "<a Onclick=\"AlterarLogin('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['au']."\"><i class=\"fa fa-edit\"></i></a>&nbsp;";
	 }
	 
	 if( ($CadUser != $LnUser['usuario']) && ($AdminAcesso == 'S')){
	  $UserOpcoes .= "<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Acesso']."\" Onclick=\"AcessoUser('".$LnUser['usuario']."')\"><i class=\"fa fa-key\"></i></a>&nbsp;";
	 }
									
	if($AdminInfo == 'S'){
		$UserOpcoes .= "<a class=\"label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['info']."\" Onclick=\"InfoUser('".$LnUser['usuario']."')\"><i class=\"fa fa-info-circle\"></i></a>&nbsp;";
	}
									
	if( ($CadUser != $LnUser['usuario']) && ($AdminMensagem == 'S') && !empty($LnUser['email']) ){
		$UserOpcoes .= "<a class=\"EnviarMensagem label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['em']."\" Onclick=\"MensagemUser('".$LnUser['usuario']."')\"><i class=\"fa fa-envelope-o\"></i></a>&nbsp;";
	}
	
	if( ($CadUser != $LnUser['usuario']) && !empty($LnUser['celular']) ){
		$UserOpcoes .= "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['EnviarSMS']."\" Onclick=\"SMSUser('".$LnUser['usuario']."')\"><i class=\"fa fa-mobile\"></i></a>&nbsp;";
	}
									
	if( ($CadUser != $LnUser['usuario']) && ($AdminBloquear == 'S') ){
		if($LnUser['bloqueado'] == "S"){
			$UserOpcoes .= "<a class=\"desbloquear label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\" Onclick=\"DesbloquearUser('".$LnUser['usuario']."')\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
		}else{
			$UserOpcoes .= "<a class=\"bloquear label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" Onclick=\"BloquearUser('".$LnUser['usuario']."')\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
		}
		
	}
	
	if( ($CadUser != $LnUser['usuario']) && ($AdminDesativar == 'S') ){
		if($LnUser['inativo'] == "S"){
			$UserOpcoes .= "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['ativar']."\" Onclick=\"AtivarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-check\"></i></a>&nbsp;";
		}else{
			$UserOpcoes .= "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desativar']."\" Onclick=\"DesativarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-times\"></i></a>&nbsp;";
		}
	}
									
	if($AdminEditar == 'S'){
		$UserOpcoes .= "<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\" Onclick=\"EditarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
	}
									
	if( ($CadUser != $LnUser['usuario']) && ($AdminExcluir == 'S') ){
		$UserOpcoes .= "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\" Onclick=\"DeletarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
	}
											
	$UserOpcoes .= "</div>";
	
	$AtivoTotalRev = AtivoTotalRev($LnUser['usuario']);
		
	$nestedData=array(); 

	$nestedData[] = $ICheckbox;
	$nestedData[] = $Foto1;
	$nestedData[] = $LnUser['nome'].$status.$statusA;
	$nestedData[] = $LnUser['usuario'];
	$nestedData[] = $LnUser['senha'];
	$nestedData[] = $EmailUser;
	$nestedData[] = $PerfilUser;
	$nestedData[] = $dataPremium;
	$nestedData[] = $AtivoTotalRev;
	$nestedData[] = $LnUser['CadUser'];
	
	if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){
	$nestedData[] = $UserOpcoes;
	}
	
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