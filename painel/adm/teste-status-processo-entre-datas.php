<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaRev = array('TesteVisualizar', 'TesteInfo', 'TesteMensagem', 'TesteBloquear', 'TesteEditar', 'TesteExcluir', 'TesteAdicionar', 'TesteLogin');
$VerificarAcesso = VerificarAcesso('teste', $ColunaRev);

$AdminVisualizar = $VerificarAcesso[0];
$AdminInfo = $VerificarAcesso[1];
$AdminMensagem = $VerificarAcesso[2];
$AdminBloquear = $VerificarAcesso[3];
$AdminEditar = $VerificarAcesso[4];
$AdminExcluir = $VerificarAcesso[5];
$AdminAdicionar = $VerificarAcesso[6];
$TesteLogin = $VerificarAcesso[7];

$ColunaRev2 = array('RevVisualizar');
$VerificarAcesso2 = VerificarAcesso('rev', $ColunaRev2);
$AdminVisualizar2 = $VerificarAcesso2[0];

$ColunaRev3 = array('UserVisualizar');
$VerificarAcesso3 = VerificarAcesso('rev', $ColunaRev3);
$AdminVisualizar3 = $VerificarAcesso3[0];
 
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
	7=> 'conexao',
	8=> 'data_premio',
	9=> 'CadUser',
);

$UserOnline = InfoUser(2);

if($status == "Ativos"){
	$DataAtual = strtotime(date('Y-m-d'));
	$PesStatus = " AND bloqueado = 'N' AND data_premio >= '".$DataAtual."'";
}
elseif($status == "Bloqueados"){
	$PesStatus = " AND bloqueado = 'S'";
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
	
	$SQL = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular FROM teste WHERE FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL." OR FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL2." OR FIND_IN_SET(CadUser,:CadUser)".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL3."";
}else{
	
	$SQL = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, data_premio, conexao, xml, celular FROM teste WHERE CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL." OR CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL2." OR CadUser = :CadUser".$PesStatus.$PesPerfil.$PesquisarEntreDatasSQL3."";
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
	
	$sconexao = $LnUser['conexao'] > 1 ? $_TRA['conexoes'] : $_TRA['conexao'];
	$pconexao = empty($LnUser['conexao']) ? 0 : $LnUser['conexao'];
	$conexao = "<span class=\"pointer label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$pconexao." ".$sconexao."\">".$pconexao."</span>";
	
	
	
	
	  $UserOpcoes = "<div class=\"form-group\">";
	  
	  if($TesteLogin == 'S'){
		$UserOpcoes .= "<a Onclick=\"AlterarLogin('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['au']."\"><i class=\"fa fa-edit\"></i></a>&nbsp;";
	 }
	  
	 if($AdminVisualizar3 == 'S'){
		$UserOpcoes .=  "<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['tu']."\"><i class=\"fa fa-user\" Onclick=\"UsuarioUser('".$LnUser['usuario']."')\"></i></a>&nbsp;";
	}
									
	if($AdminVisualizar2 == 'S'){
		$UserOpcoes .= "<a class=\"label label-default\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['tr']."\" Onclick=\"RevendedorUser('".$LnUser['usuario']."')\"><i class=\"fa fa-users\"></i></a>&nbsp;";
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
									
	if($AdminEditar == 'S'){
		$UserOpcoes .= "<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\" Onclick=\"EditarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
	}
									
	if( ($CadUser != $LnUser['usuario']) && ($AdminExcluir == 'S') ){
		$UserOpcoes .= "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\" Onclick=\"DeletarUser('".$LnUser['usuario']."')\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
	}
											
	$UserOpcoes .= "</div>";
	
	$ConvertDataPremium = ConvertDataPremium($LnUser['data_premio']);
	
	if($LnUser['xml'] == "S"){
		$Premium = "<span id=\"StatusDerrubar".$LnUser['id']."\"><span onclick=\"XMLUserRem('".$LnUser['usuario']."', 'StatusDerrubar".$LnUser['id']."');\" class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['anx']."\">".$_TRA['anx'][0]."</span></span>&nbsp;".$ConvertDataPremium;
	}
	else{
		$Premium = "<span id=\"StatusDerrubar".$LnUser['id']."\"><span onclick=\"XMLUserAdd('".$LnUser['usuario']."', 'StatusDerrubar".$LnUser['id']."');\" class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['fdx']."\">".$_TRA['fdx'][0]."</span></span>&nbsp;".$ConvertDataPremium;
	}
	
		
	$nestedData=array(); 

	$nestedData[] = $ICheckbox;
	$nestedData[] = $Foto1;
	$nestedData[] = $LnUser['nome'].$status;
	$nestedData[] = $LnUser['usuario'];
	$nestedData[] = $LnUser['senha'];
	$nestedData[] = $EmailUser;
	$nestedData[] = $PerfilUser;
	$nestedData[] = $conexao;
	$nestedData[] = $Premium;
	$nestedData[] = $LnUser['CadUser'];
	
	if( ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') || ($AdminVisualizar2 == 'S') || ($AdminVisualizar3 == 'S') ){	
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