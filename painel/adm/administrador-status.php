<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminVisualizar', 'AdminAcesso', 'AdminInfo', 'AdminMensagem', 'AdminBloquear', 'AdminDesativar', 'AdminEditar', 'AdminExcluir', 'AdminAdicionar', 'AdminLogin');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);

$AdminVisualizar = $VerificarAcesso[0];
$AdminAcesso = $VerificarAcesso[1];
$AdminInfo = $VerificarAcesso[2];
$AdminMensagem = $VerificarAcesso[3];
$AdminBloquear = $VerificarAcesso[4];
$AdminDesativar = $VerificarAcesso[5];
$AdminEditar = $VerificarAcesso[6];
$AdminExcluir = $VerificarAcesso[7];
$AdminLogin = $VerificarAcesso[8];

if($AdminVisualizar == 'S'){

$UserOnline = InfoUser(2);
$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$status = (isset($_POST['status'])) ? $_POST['status'] : '';

if($status == "Ativos"){
	$PesStatus = " AND bloqueado = 'N' AND inativo = 'N'";
}
elseif($status == "Bloqueados"){
	$PesStatus = " AND bloqueado = 'S'";
}
elseif($status == "Inativos"){
	$PesStatus = " AND inativo = 'S'";
}
else{
	$PesStatus = "";
}

if($CadUser == "Todos"){
	$CadUser = ArvoreAdmin($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$SQLUser = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, inativo, celular FROM admin WHERE FIND_IN_SET(CadUser,'".$CadUser."')".$PesStatus."";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->execute();
}else{
	$SQLUser = "SELECT id, CadUser, nome, usuario, senha, email, foto, perfil, bloqueado, inativo, celular FROM admin WHERE CadUser = :CadUser".$PesStatus."";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
}
?>

<table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="5"><input type="checkbox" name="TotalAll" id="TotalAll" class="MarcarAll" OnClick="marcardesmarcar();"></th>
                                    	<th><?php echo $_TRA['foto']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['user']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <?php
										if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){
                                        echo "<th>".$_TRA['opcoes']."</th>";
										}
										?>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
										while($LnUser = $SQLUser->fetch()){
											
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
											
										$ICheckbox = ($UserOnline == $LnUser['usuario']) ? "<input type=\"checkbox\" disabled>" : "<input type=\"checkbox\" class=\"MarcarTodos\" name=\"SelectUser[]\" id=\"SelectUser\" value=\"".$LnUser['usuario']."\" Onclick=\"VerificarCheck()\">";
											
										if(empty($LnUser['perfil'])){
											$perfil = "";
										}
										else{
											$perfil = SelecionarPerfil($LnUser['perfil']);
										}
											
										$Foto = Foto($LnUser['foto']);
										echo "
                                        <tr>
											<td width=\"5\">".$ICheckbox."</td>
											<td><img class=\"pointer\" src=\"".$Foto."\" alt=\"".$LnUser['nome']."\" height=\"32\" width=\"32\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['nome']."\"></td>
                                        	<td>".$LnUser['nome'].$status.$statusA."</td>
                                        	<td>".$LnUser['usuario']."</td>
                                        	<td>".$LnUser['senha']."</td>";
											
											if(!empty($LnUser['email'])){
                                        	echo "<td><span style=\"display: none;\">".$LnUser['email']."</span><span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$LnUser['email']."\"><i class=\"fa fa-at\"></i></span></td>";
											}
											else{
											echo "<td><span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['eunpede']."\"><i class=\"fa fa-at\"></i></span></td>";
											}

											echo "<td><div class=\"form-group\"><span style=\"display: none;\">".$LnUser['perfil']."</span>".$perfil."</div></td>
											<td>".$LnUser['CadUser']."</td>";
										
									if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){	
                                    echo "<td><div class=\"form-group\">";
									
									if( ($CadUser != $LnUser['usuario']) && ($AdminLogin == 'S')){
									echo "<a Onclick=\"AlterarLogin('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['au']."\"><i class=\"fa fa-edit\"></i></a>&nbsp;";
									}
										
									if( ($UserOnline != $LnUser['usuario']) && ($AdminAcesso == 'S') ){
									echo "<a Onclick=\"AcessoUser('".$LnUser['usuario']."')\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Acesso']."\"><i class=\"fa fa-key\"></i></a>&nbsp;";
									}
									
									if($AdminInfo == 'S'){
									echo "<a Onclick=\"InfoUser('".$LnUser['usuario']."')\" class=\"label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['info']."\"><i class=\"fa fa-info-circle\"></i></a>&nbsp;";
									}
									
									if( ($UserOnline != $LnUser['usuario']) && ($AdminMensagem == 'S') && !empty($LnUser['email']) ){
									echo "<a Onclick=\"MensagemUser('".$LnUser['usuario']."')\" class=\"label label-primary\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['em']."\"><i class=\"fa fa-envelope-o\"></i></a>&nbsp;";
									}
									
									if( ($CadUser != $LnUser['usuario']) && !empty($LnUser['celular']) ){
									echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['EnviarSMS']."\" Onclick=\"SMSUser('".$LnUser['usuario']."')\"><i class=\"fa fa-mobile\"></i></a>&nbsp;";
									}
									
									if( ($UserOnline != $LnUser['usuario']) && ($AdminBloquear == 'S') ){
									if($LnUser['bloqueado'] == "S"){
									echo "<a Onclick=\"DesbloquearUser('".$LnUser['usuario']."')\" class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
									}else{
									echo "<a Onclick=\"BloquearUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}
									}
									
									if( ($UserOnline != $LnUser['usuario']) && ($AdminDesativar == 'S') ){
									if($LnUser['inativo'] == "S"){
									echo "<a Onclick=\"AtivarUser('".$LnUser['usuario']."')\" class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['ativar']."\"><i class=\"fa fa-check\"></i></a>&nbsp;";
									}else{
									echo "<a Onclick=\"DesativarUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desativar']."\"><i class=\"fa fa-times\"></i></a>&nbsp;";
									}
									}
									
									if($AdminEditar == 'S'){
									echo "<a Onclick=\"EditarUser('".$LnUser['usuario']."')\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
									}
									
									if( ($UserOnline != $LnUser['usuario']) && ($AdminExcluir == 'S') ){
									echo "<a Onclick=\"DeletarUser('".$LnUser['usuario']."')\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
									}
											
									echo "</div>
											
											</td>";
									}
											
                                       echo "</tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
          
	<!-- START THIS PAGE PLUGINS-->        
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>