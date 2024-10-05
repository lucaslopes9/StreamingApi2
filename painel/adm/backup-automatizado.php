<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesBackup');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesBackup = $VerificarAcesso[0];

if($OpcoesBackup == 'S'){

$SQL = "SELECT * FROM backup_automatizado";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['opcoes']; ?></li>
                    <li class="active">Backup Automatizado</li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-cloud-upload"></span> Backup Automatizado</h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
                                echo "<button type=\"button\" onclick=\"Backup();\" class=\"btn btn-info active\">".$_TRA['config']."</button>";
								echo "&nbsp;&nbsp;<button type=\"button\" onclick=\"BackupServer();\" class=\"btn btn-warning active\">Configurar Servidor</button>";
								?>
                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="StatusBackupConf table datatable">
                               <thead>
                               		<tr>
                                        <th width="150"><?php echo $_TRA['Status']; ?></th>
                                        <th><?php echo $_TRA['Tempo']; ?></th>
                                        <th><?php echo $_TRA['Backupem']; ?></th>
                                        <th>Servidor</th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								while($Ln = $SQL->fetch()){
									
								$SQLServer = "SELECT nome FROM server WHERE id = :id";
								$SQLServer = $painel_geral->prepare($SQLServer);
								$SQLServer->bindParam(':id', $Ln['server'], PDO::PARAM_STR);
								$SQLServer->execute();
								$LnServer = $SQLServer->fetch();
								$NomeServer = empty($LnServer['nome']) ? "-" : $LnServer['nome'];
								
								if($Ln['status'] == "S"){
									$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado']."</span>";
								}else{
									$status = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Desativado']."\">".$_TRA['Desativado']."</span>";
								}
								
									if($Ln['tempo'] == 1){
										$tempo = "1 ".$_TRA['eeem']." 1 ".$_TRA['Hora'];
									}
									elseif($Ln['tempo'] == 2){
										$tempo = "2 ".$_TRA['eeem']." 2 ".$_TRA['Horas'];
									}
									elseif($Ln['tempo'] == 3){
										$tempo = "3 ".$_TRA['eeem']." 3 ".$_TRA['Horas'];
									}
									elseif($Ln['tempo'] == 6){
										$tempo = "6 ".$_TRA['eeem']." 6 ".$_TRA['Horas'];
									}
									elseif($Ln['tempo'] == 12){
										$tempo = "12 ".$_TRA['eeem']." 12 ".$_TRA['Horas'];
									}
									elseif($Ln['tempo'] == 24){
										$tempo = "1 ".$_TRA['dia']." ".$_TRA['eeem']." 1 ".$_TRA['dia'];
									}
									elseif($Ln['tempo'] == 48){
										$tempo = "2 ".$_TRA['dias']." ".$_TRA['eeem']." 2 ".$_TRA['dias'];
									}
									elseif($Ln['tempo'] == 72){
										$tempo = "3 ".$_TRA['dias']." ".$_TRA['eeem']." 3 ".$_TRA['dias'];
									}
									elseif($Ln['tempo'] == 96){
										$tempo = "4 ".$_TRA['dias']." ".$_TRA['eeem']." 4 ".$_TRA['dias'];
									}
									elseif($Ln['tempo'] == 120){
										$tempo = "5 ".$_TRA['dias']." ".$_TRA['eeem']." 5 ".$_TRA['dias'];
									}
									elseif($Ln['tempo'] == 144){
										$tempo = "6 ".$_TRA['dias']." ".$_TRA['eeem']." 6 ".$_TRA['dias'];
									}
									elseif($Ln['tempo'] == 168){
										 $tempo = "7 ".$_TRA['dias']." ".$_TRA['eeem']." 7 ".$_TRA['dias'];
									}
							
							    echo "<tr>
											<td>".$status."</td>
                                        	<td>".$tempo."</td>
                                        	<td>".date('d/m/Y \&\a\g\r\a\v\e\;\s H\h', $Ln['horario'])."</td>
											<td>".$NomeServer."</td>
											";
											
								echo "</tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>  
                    
                   
                   
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
                                echo "<button type=\"button\" onclick=\"FazerBackupAgora();\" class=\"btn btn-danger active\">Fazer Backup Agora</button>";
								echo "&nbsp;&nbsp;<button type=\"button\" onclick=\"AtualizarBackup();\" class=\"btn btn-success active\">Atualizar</button>";
								?>
                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela2" class="StatusBackupDis table datatable">
                               <thead>
                               		<tr>
                                        <th>Tipo</th>
                                        <th>Data do Backup</th>
                                        <th>Tamanho</th>
                                        <th>Opção</th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								$SQL = "SELECT * FROM arquivo_backup";
								$SQL = $painel_geral->prepare($SQL);
								$SQL->execute();
								while($Ln = $SQL->fetch()){
								
							    echo "<tr>
											<td>".$Ln['tipo']."</td>
                                        	<td>".date('d/m/Y \&\a\g\r\a\v\e\;\s H:i:s', $Ln['data'])."</td>
											<td>".convertmb($Ln['size'])."</td>
											<td><a onclick=\"RestaurarBackup('".$Ln['id']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Restaurar Backup Agora?\"><i class=\"fa fa-refresh\"></i></a></td>
											";
											
								echo "</tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div> 
                   
                   

                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?> 
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>  
		
		function Backup(){ 
			
				panel_refresh($(".StatusBackupConf")); 
 						
				$.post('ScriptModalBackupAutomatizado.php', function(resposta) {
					
				setTimeout(panel_refresh($(".StatusBackupConf")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
			
		function BackupServer(){ 
			
				panel_refresh($(".StatusBackupConf")); 
 						
				$.post('ScriptModalBackupServer.php', function(resposta) {
					
				setTimeout(panel_refresh($(".StatusBackupConf")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
			
		function FazerBackupAgora(){
 				
				var id = 'BackupAgora';
 				var titulo = 'Fazer Backup Agora?';
				var texto = 'Tem certeza que deseja fazer backup agora?';
				var tipo = 'success';
				var url = 'EnviarFazerBackupAutomatizado';
				var fa = 'fa fa-refresh';  
			
				panel_refresh($(".StatusBackupDis")); 
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					
					setTimeout(panel_refresh($(".StatusBackupDis")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
			
		function RestaurarBackup(id){
 				
 				var titulo = 'Restaurar Backup?';
				var texto = 'Tem certeza que deseja restaurar o banco?';
				var tipo = 'info';
				var url = 'EnviarFazerBackupRestaurar';
				var fa = 'fa fa-refresh';  
			
				panel_refresh($(".StatusBackupDis")); 
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					
					setTimeout(panel_refresh($(".StatusBackupDis")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
			
		function AtualizarBackup(){
 				
				var id = 'Atualizar';
 				var titulo = 'Atualizar Backup?';
				var texto = 'Tem certeza que deseja atualizar o backup?';
				var tipo = 'info';
				var url = 'EnviarFazerBackupAtualizar';
				var fa = 'fa fa-refresh';  
			
				panel_refresh($(".StatusBackupDis")); 
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					
					setTimeout(panel_refresh($(".StatusBackupDis")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		</script>

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>