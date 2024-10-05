<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('EmailModeloVisualizar', 'EmailModeloAdicionar', 'EmailModeloBloquear', 'EmailModeloEditar', 'EmailModeloExcluir', 'EmailModeloPreferencias');
$VerificarAcesso = VerificarAcesso('email_modelo', $ColunaAcesso);

$EmailModeloVisualizar = $VerificarAcesso[0];
$EmailModeloAdicionar = $VerificarAcesso[1];
$EmailModeloBloquear = $VerificarAcesso[2];
$EmailModeloEditar = $VerificarAcesso[3];
$EmailModeloExcluir = $VerificarAcesso[4];
$EmailModeloPreferencias = $VerificarAcesso[5];

if($EmailModeloVisualizar == 'S'){
	
$CadUser = InfoUser(2);
$SQL = "SELECT id, tipo, assunto, mensagem, bloqueado FROM email_modelo WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['email']; ?></li>
                    <li class="active"><?php echo $_TRA['Modelo']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-file-o"></span> <?php echo $_TRA['Modelo']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($EmailModeloAdicionar == 'S'){
                                echo "<button type=\"button\" onclick=\"AdicionarModelo();\" class=\"Adicionar btn btn-info active\">".$_TRA['Adicionar']."</button>";
								}
								
								if($EmailModeloPreferencias == 'S'){
                                echo "&nbsp;&nbsp;<button onclick=\"PreferenciasModelo();\" type=\"button\" class=\"Preferencias btn btn-danger active\">".$_TRA['Preferencias']."</button>";
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
                                    	<th width="150"><?php echo $_TRA['Tipo']; ?></th>
                                        <th><?php echo $_TRA['Assunto']; ?></th>
                                        <th><?php echo $_TRA['Mensagem']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
										while($Ln = $SQL->fetch()){
											
										if($Ln['tipo'] == "Painel"){
											$tipo = $_TRA['Preferencia'];
										}
										else{
											$tipo = $_TRA['email'];
										}
										
										if($Ln['bloqueado'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}
										else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
										
										echo "
                                        <tr>
											<td>".$tipo.$status."</td>
                                        	<td>".$Ln['assunto']."</td>
                                        	<td>".$Ln['mensagem']."</td>
                                       	    <td><div class=\"form-group\">";
								
								if($EmailModeloBloquear == 'S'){
									if($Ln['bloqueado'] == "S"){
									echo "<a onclick=\"DesBloquearModelo('".$Ln['id']."', '".$Ln['assunto']."');\" class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
									}else{
									echo "<a onclick=\"BloquearModelo('".$Ln['id']."', '".$Ln['assunto']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}	
								}
								
								if($EmailModeloEditar == 'S'){
								echo "<a onclick=\"EditarModelo('".$Ln['id']."');\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								}
								
								if($EmailModeloExcluir == 'S'){
								echo "<a onclick=\"DeletarModelo('".$Ln['id']."', '".$Ln['assunto']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
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
		if($EmailModeloExcluir == 'S'){
		?>
		function DeletarModelo(id, assunto){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+assunto+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarEmailModelo';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($EmailModeloBloquear == 'S'){
		?>
		function BloquearModelo(id, assunto){
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+assunto+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearEmailModelo';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		function DesBloquearModelo(id, assunto){
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+assunto+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearEmailModelo';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($EmailModeloEditar == 'S'){
		?>
		function EditarModelo(id){
 							
				panel_refresh($(".page-container"));
			
				$.post('ScriptModalEditarEmailModelo.php', {id: id}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($EmailModeloAdicionar == 'S'){
		?>
		function AdicionarModelo(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalAdicionarEmailModelo.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		if($EmailModeloPreferencias == 'S'){
		?>
		function PreferenciasModelo(){
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalPreferenciasEmailModelo.php', function(resposta) {
					
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