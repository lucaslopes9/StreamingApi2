<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PerfilVisualizar', 'PerfilAdicionar', 'PerfilBloquear', 'PerfilEditar', 'PerfilExcluir');
$VerificarAcesso = VerificarAcesso('perfil', $ColunaAcesso);

$PerfilVisualizar = $VerificarAcesso[0];
$PerfilAdicionar = $VerificarAcesso[1];
$PerfilBloquear = $VerificarAcesso[2];
$PerfilEditar = $VerificarAcesso[3];
$PerfilExcluir = $VerificarAcesso[4];

if($PerfilVisualizar == 'S'){

$SQLCSP = "SELECT id, painel, imagem, nome, valorcsp, url, porta, tipo, bloqueado FROM perfil";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['CSP']; ?></li>
                    <li class="active"><?php echo $_TRA['Perfil']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-bars"></span> <?php echo $_TRA['Perfil']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($PerfilAdicionar == 'S'){
                                echo "<button type=\"button\" onclick=\"AdicionarPerfil();\" class=\"Adicionar btn btn-info active\">".$_TRA['Adicionar']."</button>";
								}
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
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="100"><?php echo $_TRA['SCSP']; ?></th>
                                        <th><?php echo $_TRA['Tipo']; ?></th>
                                        <th><?php echo $_TRA['Imagem']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['valorcsp']; ?></th>
                                        <th><?php echo $_TRA['Url']; ?></th>
                                        <th><?php echo $_TRA['Porta']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								while($LnCSP = $SQLCSP->fetch()){
											
								$SQLPainel = "SELECT nome FROM painel WHERE id = :id";
								$SQLPainel = $painel_geral->prepare($SQLPainel);
								$SQLPainel->bindParam(':id', $LnCSP['painel'], PDO::PARAM_INT);
								$SQLPainel->execute();
								$LnPainel = $SQLPainel->fetch();
										
										if($LnCSP['bloqueado'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
										
								if($LnCSP['tipo'] == "SAT"){
									$tipo = $_TRA['satelite'];
								}
								else{
									$tipo = $_TRA['cabo'];
								}
										
										echo "
                                        <tr>
											<td>".$LnPainel['nome'].$status."</td>
											<td>".$tipo."</td>
                                        	<td>".SelecionarPerfil($LnCSP['valorcsp'])."</td>
                                        	<td>".$LnCSP['nome']."</td>
                                        	<td>".ValorPerfil($LnCSP['valorcsp'])."</td>
                                        	<td>".$LnCSP['url']."</td>
											<td>".$LnCSP['porta']."</td>
                                       	    <td><div class=\"form-group\">";
								
								if($PerfilBloquear == "S"){
									if($LnCSP['bloqueado'] == "S"){
										echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\" onclick=\"DesBloquearPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\"></i></a>&nbsp;";
									}else{
										echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" onclick=\"BloquearPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}	
								}
								
								if($PerfilEditar == 'S'){
								echo "<a id=\"".$LnCSP['id']."\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\" onclick=\"EditarPerfil('".$LnCSP['id']."');\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								}
								
								if($PerfilExcluir == 'S'){
									echo "<a onclick=\"DeletarPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								}
									echo "</div>
										</td>
                                      </tr>
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
		<?php
		if($PerfilExcluir == 'S'){
		?>
		function DeletarPerfil(id, nome){
			 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarPerfil';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($PerfilBloquear == "S"){
		?>
		function BloquearPerfil(id, nome){ 
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearPerfil';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		function DesBloquearPerfil(id, nome){ 
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearPerfil';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($PerfilEditar == 'S'){
		?>
		function EditarPerfil(id){  
 							
				panel_refresh($(".page-container")); 
				$.post('ScriptModalPerfil.php', {id: id}, function(resposta) {
				
				setTimeout(panel_refresh($(".page-container")),500);	
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($PerfilAdicionar == 'S'){
		?>
		function AdicionarPerfil(){ 
			
				panel_refresh($(".page-container")); 
 						
				$.post('ScriptModalPerfilAdicionar.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		?>
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