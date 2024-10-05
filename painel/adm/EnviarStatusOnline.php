<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusOnline');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];

$ColunaAdmin = array('UserBloquear');
$VerificarAcesso = VerificarAcesso('user', $ColunaAdmin);
$AdminBloquear = $VerificarAcesso[0];

$ColunaTeste = array('TesteBloquear');
$VerificarAcessoTeste = VerificarAcesso('teste', $ColunaTeste);
$TesteBloquear = $VerificarAcessoTeste[0];

if($StatusOnline == 'S'){

$caduser = empty($_POST['caduser']) ? '' : $_POST['caduser'];
$rev = empty($_POST['rev']) ? '' : $_POST['rev'];
$status = empty($_POST['status']) ? '' : $_POST['status'];
$perfil = empty($_POST['perfil']) ? '' : $_POST['perfil'];

if(empty($caduser)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sur'], "danger");
}
elseif(empty($rev)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['edr'], "danger");
}
elseif(empty($status)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sus'], "danger");
}
elseif(empty($perfil)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sup'], "danger");
}
else{
	
	$VerificarStatusOnline = VerificarStatusOnline($caduser, $rev, $status, $perfil);
?>

<div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th><?php echo $_TRA['Status']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <th><?php echo $_TRA['ce']; ?></th>
                                        <th><?php echo $_TRA['ip']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['Canal']; ?></th>
                                        <th><?php echo $_TRA['op']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
									
									for($i=0; $i<count($VerificarStatusOnline); $i++){
										
									$PerfilAtual = "[".$VerificarStatusOnline[$i][4]."]";
									$perfil = SelecionarPerfil($PerfilAtual);
									
									$SQLUser = "SELECT CadUser, nome FROM usuario WHERE usuario = :usuario";
									$SQLUser = $painel_user->prepare($SQLUser);
									$SQLUser->bindParam(':usuario', $VerificarStatusOnline[$i][0], PDO::PARAM_STR);
									$SQLUser->execute();
									$LnUser = $SQLUser->fetch();
										
										if($VerificarStatusOnline[$i][3] == "false"){
											$status = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ocioso']."\">".$_TRA['Ocioso']."</span>";
										}
										else{
											$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Online']."\">".$_TRA['Online']."</span>";
										}
										
									echo "	
                                        <tr>
											<td width=\"50\">".$status."</td>
											<td>".$LnUser['nome']."</td>
											<td>".$VerificarStatusOnline[$i][0]."</td>
											<td>".$LnUser['CadUser']."</td>
											<td>".OrganizarHora($VerificarStatusOnline[$i][1])."</td>
											<td><span id=\"StatusIP".$i."\">".$VerificarStatusOnline[$i][2]."&nbsp;<a class=\"label label-info\" Onclick=\"InfoIP('".$VerificarStatusOnline[$i][2]."', '".$VerificarStatusOnline[$i][0]."', '#StatusIP".$i."')\"><i class=\"fa fa-exchange\"></i></a>&nbsp;</span></td>
											<td>".$perfil."</td>
											<td>".$VerificarStatusOnline[$i][5]."</td>
											<td>".$VerificarStatusOnline[$i][6]."</td>
                                       	    <td><div class=\"form-group\">
											<span id=\"StatusDerrubar".$i."\">
											<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Derrubar']."\" Onclick=\"DerrubarUsuario('".$VerificarStatusOnline[$i][0]."', '".$PerfilAtual."', 'StatusDerrubar".$i."')\"><i class=\"fa fa-retweet\"></i></a>&nbsp;";
											
											if( ($AdminBloquear == 'S') || ($TesteBloquear == 'S') ){
												echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" Onclick=\"BloquearStatusUser('".$VerificarStatusOnline[$i][0]."')\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
											}
											
											echo "</span></div></td>";
									
								 	echo "</tr>";
									}
								  
										?>
										
                                            </tbody>
                                        </table>
                                    </div>
                                    
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
                    
        <script type="text/javascript" src="js/plugins.js"></script>
        
        <script type='text/javascript'> 
		function DerrubarUsuario(usuario, perfil, status){
 		
				panel_refresh($(".page-container"));
			
				$.post('EnviarDerrubarUser.php', {usuario: usuario, perfil: perfil}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#"+status+"").html('');
				$("#"+status+"").html(resposta);
				});
				
		}
		
		<?php
		if( ($AdminBloquear == 'S') || ($TesteBloquear == 'S') ){
		?>
		function BloquearStatusUser(usuario){ 
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+usuario+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearUserTeste';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: usuario, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		?>
		
		function InfoIP(ip, usuario, div){
			
				$(div).html("<center><img src=\"img/fileinput/loading.gif\"></center>");
			
				$.post('InfoIP.php', {ip: ip, usuario: usuario}, function(resposta) {
				$(div).html('');
				$(div).html(resposta.trim());
				});
				
		}
		</script>

	
<?php
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>